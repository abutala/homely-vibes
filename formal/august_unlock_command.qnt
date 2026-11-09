// AugustUnlock: one door's one lock command at a time, and what a tap, a
// timeout, a phone nap and a return to the foreground do to it.
//
// The app (AugustUnlock/AugustUnlock/DoorController.swift, one per door) sends
// one lock/unlock at a time per door. On the phone (2026-11-01) it sat in "Unlocking…"
// for good after the phone slept, and "Change Lock" was dead meanwhile.
// This model asks: with the 30 s deadline, the wall-clock check on resume
// and live Change Lock, can a command still hold the screen, can a return
// to the app unlock a door by itself after a timeout, and what does a tap
// during a cloud command do at the lock?
//
// Time is in whole seconds. The phone can nap (`asleep`): while it naps no
// reply, no Bluetooth timer and no deadline fires, but the wall clock runs,
// which is the stall the phone showed. A command goes over Bluetooth first
// and may fall to the cloud; a cancelled Bluetooth command not yet written
// never reaches the lock (a written one runs to its result on the link, in
// order, so the screen's next state is still the last command's), a
// cancelled cloud command stays with August and runs later. What the screen
// shows against what the lock did is ghost_order.qnt.
//
// ASSUMPTION A1: August runs every cloud command it received, in order, once
//   the lock answers; the phone cannot recall one (Logbook 2026-10-23).
// Out of scope: sign-in and token refresh; the 5-minute background exit;
//   Bluetooth jams; the widget's taps (they share the client's per-lock
//   command gate with the screen, which gate.qnt checks).
//
// max-steps: 40  (a stall needs `limit` + 1 ticks around a nap; 40 covers
//   two commands with a nap, a change of lock and a return each)

module august_unlock_command {
  // The 30 s deadline (CommandDeadline) and its wall-clock check on resume.
  const hasDeadline: bool
  // "Change Lock" and "Sign Out" stay enabled during a command.
  const changeLockLive: bool
  // A timeout while the app is away suppresses the next return's auto-unlock.
  const awayFlag: bool
  // ASSUMPTION A2: on wake, a deadline that passed during the nap fires at
  // once (`Task.sleep` on the continuous clock). Unmeasured on the phone;
  // the `resumeOnly` instance drops it and leans on the resume check alone.
  const wakeFiresDeadline: bool
  // A tap after a failed or timed-out command repeats it (TRIAL 2026-11-07);
  // before, the door shown unknown made every such tap unlock.
  const retryRule: bool
  // A return or a pick sends an unlock (every instance before tapToUnlock).
  // Off, only a tap sends: the "Change Lock" action below is then Sign Out.
  const unlockOnOpen: bool

  type Op = Idle | Unlocking | Locking | Done
  type Retry = NoRetry | RetryUnlock | RetryLock
  type Transport = NoTransport | Ble | Cloud
  type Door = Locked | Unlocked | Unknown
  type App = Foreground | Background

  type State = {
    op: Op,
    transport: Transport,
    door: Door,
    app: App,
    asleep: bool,
    now: int,
    started: int,
    lastTap: int,
    // A timeout happened while the app was away and no command has been
    // sent since; the design clears it on return (awayFlag) or ignores it.
    awayTimedOut: bool,
    // The direction of the command that last failed or timed out, until a
    // success or an open.
    retry: Retry,
    // Cloud commands August still holds after the phone stopped waiting.
    heldAtAugust: int,
    // History, for the properties.
    surpriseMoves: int,       // the lock ran a command the phone had given up on
    autoUnlockAfterAway: int, // a return to the app unlocked after an away timeout
    changeLockRefused: int,   // Change Lock was wanted and disabled
    unlockAfterFailedLock: int, // a tap right after a failed lock unlocked
    sentWithoutTap: int       // a command went out with no tap
  }

  var st: State

  // Time units are abstract: the app's 30 s limit and 0.75 s tap gap keep
  // their ratio's meaning (a limit of several ticks, a gap of one), and a
  // small limit keeps a stall reachable for the randomized search.
  val limit: int = 3
  val tapGap: int = 1

  action init = st' = {
    op: Idle, transport: NoTransport, door: Unknown, app: Foreground,
    asleep: false, now: 0, started: 0, lastTap: -1,
    awayTimedOut: false, retry: NoRetry, heldAtAugust: 0,
    surpriseMoves: 0, autoUnlockAfterAway: 0, changeLockRefused: 0, unlockAfterFailedLock: 0,
    sentWithoutTap: 0
  }

  pure def inProgress(s: State): bool = s.op == Unlocking or s.op == Locking

  // `run`: start a command; a command still on the cloud is left with August.
  pure def send(s: State, unlocking: bool): State =
    s.with("op", if (unlocking) Unlocking else Locking)
     .with("transport", Ble)
     .with("started", s.now)
     .with("awayTimedOut", false)
     .with("heldAtAugust", if (s.transport == Cloud and inProgress(s)) s.heldAtAugust + 1 else s.heldAtAugust)

  pure def failedDirection(s: State): Retry =
    if (s.op == Unlocking) RetryUnlock else if (s.op == Locking) RetryLock else s.retry

  pure def expired(s: State): bool = hasDeadline and inProgress(s) and s.now - s.started >= limit

  // `timeOutCommand`
  pure def timeOut(s: State): State =
    s.with("op", Done).with("door", Unknown).with("retry", failedDirection(s))
     .with("heldAtAugust", if (s.transport == Cloud) s.heldAtAugust + 1 else s.heldAtAugust)
     .with("transport", NoTransport)
     .with("awayTimedOut", s.app == Background)

  // --- actions ---------------------------------------------------------

  // `performToggle`: a second tap within the gap is the same tap; a tap
  // during a command sends the opposite; after a failure, the failed command
  // again (retryRule); otherwise lock if shown unlocked.
  action tap = all {
    st.app == Foreground, not(st.asleep), st.now - st.lastTap >= tapGap,
    val unlocking =
      if (inProgress(st)) st.op == Locking
      else if (retryRule and st.retry != NoRetry) st.retry == RetryUnlock
      else st.door != Unlocked
    val afterFailedLock = not(inProgress(st)) and st.retry == RetryLock and unlocking
    st' = send(st, unlocking).with("lastTap", st.now)
           .with("unlockAfterFailedLock", if (afterFailedLock) st.unlockAfterFailedLock + 1 else st.unlockAfterFailedLock)
  }

  // Bluetooth setup or the write failed: the command falls to the cloud.
  action bleFallsToCloud = all {
    inProgress(st), st.transport == Ble, not(st.asleep),
    st' = st.with("transport", Cloud)
  }

  action replyOk = all {
    inProgress(st), not(st.asleep),
    st' = st.with("op", Done).with("transport", NoTransport).with("retry", NoRetry)
           .with("door", if (st.op == Unlocking) Unlocked else Locked)
  }

  action replyFail = all {
    inProgress(st), not(st.asleep),
    st' = st.with("op", Done).with("transport", NoTransport).with("door", Unknown)
           .with("retry", failedDirection(st))
  }

  // The 2 s idle reset after a result.
  action settle = all { st.op == Done, st' = st.with("op", Idle) }

  // August runs a command the phone gave up on (A1).
  action augustRuns = all {
    st.heldAtAugust > 0,
    st' = st.with("heldAtAugust", st.heldAtAugust - 1).with("surpriseMoves", st.surpriseMoves + 1)
  }

  // One second passes. Awake, the deadline fires; asleep, nothing runs.
  action tick = all {
    val later = st.with("now", st.now + 1)
    st' = if (not(later.asleep) and expired(later)) timeOut(later) else later
  }

  // Screen off backgrounds the app's scene, so a nap always starts in the
  // background; wake fires a passed deadline under A2.
  action sleep = all { not(st.asleep), st' = st.with("asleep", true).with("app", Background) }
  action wake = all {
    st.asleep,
    val awake = st.with("asleep", false)
    st' = if (wakeFiresDeadline and expired(awake)) timeOut(awake) else awake
  }

  action toBackground = all {
    st.app == Foreground, st' = st.with("app", Background)
  }

  // The scenePhase `.active` branch after a real background: a command past
  // its deadline fails now. With unlockOnOpen an away timeout clears instead
  // of unlocking and an idle app unlocks. Without it a return sends nothing:
  // an idle door with no retry becomes unknown, so the next tap unlocks.
  action toForeground = all {
    st.app == Background, not(st.asleep),
    val back = st.with("app", Foreground)
    st' = if (expired(back)) timeOut(back).with("awayTimedOut", false)
          else if (inProgress(back)) back
          else if (not(unlockOnOpen))
            if (back.retry == NoRetry) back.with("door", Unknown).with("op", Idle) else back
          else if (awayFlag and back.awayTimedOut) back.with("awayTimedOut", false)
          else send(back.with("retry", NoRetry), true)
                 .with("sentWithoutTap", back.sentWithoutTap + 1)
                 .with("autoUnlockAfterAway",
                   if (back.awayTimedOut) back.autoUnlockAfterAway + 1 else back.autoUnlockAfterAway)
  }

  // "Change Lock": cancels the command (a cloud one stays with August),
  // then the picker's choice unlocks. Disabled during a command before.
  // Without unlockOnOpen it is Sign Out: the same cancel, and nothing is sent.
  action changeLock = all {
    st.app == Foreground, not(st.asleep),
    st' = if (inProgress(st) and not(changeLockLive))
            st.with("changeLockRefused", st.changeLockRefused + 1)
          else if (not(unlockOnOpen))
            st.with("op", Idle).with("door", Unknown).with("retry", NoRetry).with("transport", NoTransport)
              .with("heldAtAugust", if (st.transport == Cloud and inProgress(st)) st.heldAtAugust + 1 else st.heldAtAugust)
          else send(st.with("door", Unknown).with("retry", NoRetry), true)
                 .with("sentWithoutTap", st.sentWithoutTap + 1)
  }

  action step = any {
    tap, bleFallsToCloud, replyOk, replyFail, settle, augustRuns, tick,
    sleep, wake, toBackground, toForeground, changeLock
  }

  // --- properties -----------------------------------------------------

  // The screen never shows a command older than the limit while the phone
  // is awake in the foreground: A2 from the 2026-11-01 report.
  val noStuckCommand: bool =
    not(st.app == Foreground and not(st.asleep) and inProgress(st) and st.now - st.started > limit)

  // A return to the app after a timeout while away never unlocks by itself.
  val noAutoUnlockAfterAwayTimeout: bool = st.autoUnlockAfterAway == 0

  // Change Lock is never refused: A1 from the report.
  val changeLockAlwaysPossible: bool = st.changeLockRefused == 0

  // The lock never runs a command the phone gave up on. Violated by design
  // (A1): a cancelled or timed-out cloud command still runs. Pinned so the
  // gap stays documented.
  val noSurpriseMoves: bool = st.surpriseMoves == 0

  // A tap right after a failed or timed-out lock never unlocks: with the
  // door unknown it used to (seen on the phone, TRIAL 2026-11-07).
  val noUnlockAfterFailedLock: bool = st.unlockAfterFailedLock == 0

  // Only a tap sends a command (Amit, 2026-11-08).
  val onlyATapSends: bool = st.sentWithoutTap == 0
}

// The app before 2026-11-01 (#57): no deadline, Change Lock disabled during a command.
module beforeDeadline {
  import august_unlock_command(hasDeadline = false, changeLockLive = false, awayFlag = false, wakeFiresDeadline = false, retryRule = false, unlockOnOpen = true).*
}

// #57 as first pushed (d7e1580): the deadline without the away flag.
module deadlineOnly {
  import august_unlock_command(hasDeadline = true, changeLockLive = true, awayFlag = false, wakeFiresDeadline = true, retryRule = false, unlockOnOpen = true).*
}

// The app after #57 (458f08d), before the retry rule.
module withDeadline {
  import august_unlock_command(hasDeadline = true, changeLockLive = true, awayFlag = true, wakeFiresDeadline = true, retryRule = false, unlockOnOpen = true).*
}

// A tap after a failure repeats the failed command (#77).
module withRetry {
  import august_unlock_command(hasDeadline = true, changeLockLive = true, awayFlag = true, wakeFiresDeadline = true, retryRule = true, unlockOnOpen = true).*
}

// The same app if A2 is false: only the wall-clock check on resume ends a
// command that stalled through a nap.
module resumeOnly {
  import august_unlock_command(hasDeadline = true, changeLockLive = true, awayFlag = true, wakeFiresDeadline = false, retryRule = true, unlockOnOpen = true).*
}

// The app now: two doors on screen, opening sends nothing, only a tap sends.
module tapToUnlock {
  import august_unlock_command(hasDeadline = true, changeLockLive = true, awayFlag = false, wakeFiresDeadline = true, retryRule = true, unlockOnOpen = false).*
}
