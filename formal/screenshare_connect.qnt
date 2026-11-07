// ScreenShare launcher (`ScreenShare/launcher.applescript`): one launch of a
// "VNC <host>" app that reaches its host through an SSH tunnel.
//
// On 2026-11-06 a tunnel app hung on "Connecting…" and left the window
// and a dead ssh behind; the next launch reused the dead tunnel and hung
// again. A refused connect showed "Connection failed" in 2 s, and the app
// still waited its full 90 s. This model asks: does a failed launch leave a
// window or a tunnel behind, can a healthy launch fail, does cleanup end a
// working session or a password prompt, is a dead session ever taken for a
// live one, and does the app reopen what the user cancelled?
//
// The world: a link (up/down); an ssh tunnel that holds the local port (live,
// or stale: its link died and ServerAliveInterval has not yet ended it); the
// remote VNC server (answers, stalls after its banner, or is off); and Screen
// Sharing's state for this connection. `stuck` counts windows from earlier
// tries that nobody closed. A session whose tunnel was stopped keeps its
// titled window for a while (`Dropping`) before its dialog shows: the
// launcher cannot tell it from a live session by its title.
// The world may also: make the banner probe lie once (a slow, loaded host),
// make a healthy connect slow (it ends after the 30 s deadline, before 90 s),
// show a password prompt on a first launch, and let the user click Cancel.
//
// ASSUMPTION A1: a connect that can finish (live tunnel, link up, server
//   answers or refuses) and is not slow finishes before the timer moves.
//   Measured: a refusal shows in under 2 s; the banner through a real tunnel in 0.21 s.
// ASSUMPTION A2: stopping the tunnel under a session or a prompt ends it;
//   the old session window turns into a dialog a moment later.
// ASSUMPTION A3: one launcher runs at a time (an applet relaunch only
//   activates the running one; only one tunnel app is configured), and
//   nobody connects by hand meanwhile.
// ASSUMPTION A4: a slow connect ends after the 30 s deadline and before 90 s.
//   The owner chose the 30 s deadline (2026-11-06): such a connect fails and gets
//   the fallback app. noFailedHealthyLaunch excludes it.
// Out of scope: the ssh `sleep 300` idle exit (never inside one attempt);
//   a session that drops after the launcher finished; localized UI text; a
//   window of a shape the launcher does not know (it offers the fallback at
//   the deadline and leaves that window and the tunnel); the time the tunnel
//   script takes (it counts against the 30 s, so a stale tunnel leaves about
//   18 s for the connect); the launcher's rule to start a retry only with
//   10 s left (it only drops attempts).
//
// max-steps: 60  (for `quint run`; `shareFinal` reaches depth 39)
// backend: tlc  (the whole state graph in about 1 s; Apalache did not finish
//   one row in 15 min at 40 steps)

module screenshare_connect {
  // The tunnel check reads an RFB banner through the tunnel; false: it only
  // checks that the local port listens (`nc -z`, main before 2026-11-06).
  const bannerProbe: bool
  // A failed attempt ends early on a "Connection failed" dialog or a hang,
  // cleans up (Cancel/OK, stop the tunnel) and retries; the launch starts by
  // clearing leftovers.
  const retryAndClean: bool
  // Leftovers are also cleared right before `open location`.
  const clearBeforeOpen: bool
  // Cleanup looks for the session window before it clears and once more
  // before it stops the tunnel, and takes a session that came up late.
  const relook: bool
  // A failed banner probe is repeated once before the tunnel is stopped.
  const reprobe: bool
  // After it stops a tunnel under a session, the launcher waits until the
  // old window has turned into its dialog before it opens the connection.
  const waitOldGone: bool
  // A window with a text field (a password prompt) stops the hang timer and
  // every cleanup; a 90 s timeout on it offers the fallback and keeps the
  // tunnel.
  const promptFreeze: bool
  // The Connecting window gone with no session and no dialog means the user
  // cancelled: the launcher leaves and does not retry.
  const userCancelExits: bool
  // One 30 s deadline for the whole launch, not a hang timer per attempt: a
  // hang ends at the deadline and no attempt starts after it. Time on a
  // password prompt does not count.
  const oneDeadline: bool

  type Net = NetUp | NetDown
  type Tunnel = NoTunnel | Live | Stale
  type Server = Ok | Stalls | Off
  type Screen = Closed | Connecting | Prompt | FailedDialog | Session | Dropping
  type Pc = Start | Probe | StartSsh | CheckNew | Open | Wait
          | GiveLook | GiveClear | GiveStop | GiveSettle | DoneOk | DoneFail | DoneUser

  type State = {
    net: Net, tunnel: Tunnel, server: Server, screen: Screen, stuck: int,
    pc: Pc, attempt: int, waited: int,
    slow: bool,             // this connect is slow (A4)
    everSlow: bool,         // a connect in this launch was slow
    elapsed: int,           // launch time spent waiting, prompts excluded
    firstLaunch: bool,      // the password is not saved yet
    userCancelled: bool,
    faults: int,
    launchHealthy: bool,    // link up and server answering since the launch began
    attemptFaults: int,     // link or server faults in this attempt
    promptLeft: bool,       // the launch ended on an open password prompt
    liveSessionKills: int,  // cleanup stopped a working session's tunnel
    promptKills: int,       // cleanup ended a password prompt
    reopenedAfterCancel: int
  }

  var st: State

  val maxAttempts: int = 3
  val hangLimit: int = 2   // 30 s per attempt; ticks are abstract (see formal/Logbook.md)
  val deadline: int = 2    // 30 s for the whole launch
  val slowAt: int = 3      // a slow connect ends here (A4)
  val waitLimit: int = 4   // 90 s
  val maxFaults: int = 3

  pure def done(s: State): bool = s.pc == DoneOk or s.pc == DoneFail or s.pc == DoneUser
  pure def working(s: State): bool = s.tunnel == Live and s.net == NetUp and s.server == Ok
  pure def isStuck(sc: Screen): bool = sc == Connecting or sc == FailedDialog
  pure def looksLikeSession(sc: Screen): bool = sc == Session or sc == Dropping

  pure def canFinish(s: State): bool =
    s.screen == Connecting and (
      s.tunnel == NoTunnel or
      (s.tunnel == Live and s.net == NetUp and
        (s.server == Off or (s.server == Ok and (not(s.slow) or s.waited >= slowAt)))))

  pure def fault(s: State): State =
    s.with("faults", s.faults + 1).with("launchHealthy", false).with("attemptFaults", s.attemptFaults + 1)

  // Cancel on busy windows, OK on "Connection failed" dialogs. Without
  // promptFreeze a prompt is assumed to sit on a busy window and goes too.
  pure def clearStuck(s: State): State =
    val promptGoes = s.screen == Prompt and not(promptFreeze)
    s.with("stuck", 0)
     .with("promptKills", if (promptGoes and working(s)) s.promptKills + 1 else s.promptKills)
     .with("screen", if (isStuck(s.screen) or promptGoes) Closed else s.screen)

  // Kill the ssh on the local port (A2).
  pure def stopTunnel(s: State): State =
    val live = s.tunnel != NoTunnel
    s.with("liveSessionKills", if (s.screen == Session and working(s)) s.liveSessionKills + 1 else s.liveSessionKills)
     .with("promptKills", if (s.screen == Prompt and working(s)) s.promptKills + 1 else s.promptKills)
     .with("screen", if (s.screen == Session and live) Dropping
                     else if (s.screen == Prompt and live) FailedDialog
                     else s.screen)
     .with("tunnel", NoTunnel)

  pure def bannerOk(s: State): bool = s.tunnel == Live and s.net == NetUp and s.server != Off

  pure def beginAttempt(s: State, n: int): State =
    s.with("pc", Probe).with("attempt", n).with("waited", 0).with("slow", false).with("attemptFaults", 0)

  action init = {
    nondet net = Set(NetUp, NetDown).oneOf()
    nondet tunnel = Set(NoTunnel, Live, Stale).oneOf()
    nondet server = Set(Ok, Stalls, Off).oneOf()
    nondet screen = Set(Closed, Connecting, FailedDialog, Session).oneOf()
    nondet firstLaunch = Set(false, true).oneOf()
    all {
      not(tunnel == Live and net == NetDown),
      not(screen == Session and tunnel == NoTunnel),
      not(screen == Session and server == Off),
      st' = {
        net: net, tunnel: tunnel, server: server, screen: screen, stuck: 0,
        pc: Start, attempt: 0, waited: 0, slow: false, everSlow: false, elapsed: 0,
        firstLaunch: firstLaunch,
        userCancelled: false, faults: 0,
        launchHealthy: net == NetUp and server == Ok, attemptFaults: 0,
        promptLeft: false, liveSessionKills: 0, promptKills: 0, reopenedAfterCancel: 0
      }
    }
  }

  // --- the launcher ---------------------------------------------------

  action start = all {
    st.pc == Start,
    st' = beginAttempt(if (retryAndClean) clearStuck(st) else st, 1)
  }

  // The banner probe may lie once (a fault); with reprobe, a second probe
  // tells the truth.
  pure def probeSays(s: State, lie: bool): bool =
    if (not(bannerProbe)) s.tunnel != NoTunnel
    else (bannerOk(s) and not(lie)) or (reprobe and bannerOk(s))

  pure def lies(s: State, lie: bool): bool = bannerProbe and lie and s.faults < maxFaults and bannerOk(s)

  // The faults counter only: a slow banner is not an unhealthy link.
  pure def spendLie(s: State, lie: bool): State =
    if (lies(s, lie)) s.with("faults", s.faults + 1) else s

  // Probe, reprobe and stop run in one shell script, microseconds apart.
  action probe = {
    nondet lie = Set(false, true).oneOf()
    all {
      st.pc == Probe,
      st' = if (probeSays(st, lies(st, lie))) spendLie(st, lie).with("pc", Open)
            else stopTunnel(spendLie(st, lie)).with("pc", StartSsh)
    }
  }

  action startSsh = all {
    st.pc == StartSsh,
    st' = if (st.net == NetDown) st.with("pc", GiveLook)
          else st.with("tunnel", Live).with("pc", if (bannerProbe) CheckNew else Open)
  }

  action checkNew = {
    nondet lie = Set(false, true).oneOf()
    all {
      st.pc == CheckNew,
      st' = if (probeSays(st, lies(st, lie))) spendLie(st, lie).with("pc", Open)
            else stopTunnel(spendLie(st, lie)).with("pc", GiveLook)
    }
  }

  // `open location`. A window with the session's title is taken as up.
  action openLocation = all {
    st.pc == Open,
    not(waitOldGone and st.screen == Dropping),
    val s = if (clearBeforeOpen) clearStuck(st) else st
    st' = if (looksLikeSession(s.screen)) s.with("pc", DoneOk)
          else s.with("stuck", if (isStuck(s.screen)) s.stuck + 1 else s.stuck)
                .with("reopenedAfterCancel", if (s.userCancelled) s.reopenedAfterCancel + 1 else s.reopenedAfterCancel)
                .with("screen", Connecting).with("waited", 0).with("pc", Wait)
  }

  action seeSession = all { st.pc == Wait, looksLikeSession(st.screen), st' = st.with("pc", DoneOk) }

  action seeFailure = all {
    st.pc == Wait, st.screen == FailedDialog, retryAndClean,
    st' = st.with("pc", GiveLook)
  }

  action seeUserCancel = all {
    st.pc == Wait, st.screen == Closed, userCancelExits,
    st' = st.with("pc", DoneUser)
  }

  pure def hangApplies(s: State): bool =
    retryAndClean and (s.screen == Connecting or (s.screen == Prompt and not(promptFreeze)))

  // Time passes while the launcher waits. Under A1 a connect that can finish
  // does so before the timer moves.
  action tick = all {
    st.pc == Wait, not(canFinish(st)), not(looksLikeSession(st.screen)),
    not(retryAndClean and st.screen == FailedDialog),
    not(userCancelExits and st.screen == Closed),
    val w = st.waited + 1
    val frozen = promptFreeze and st.screen == Prompt
    val t = st.with("waited", w).with("elapsed", if (frozen) st.elapsed else st.elapsed + 1)
    val hung = if (oneDeadline) t.elapsed >= deadline else w >= hangLimit
    st' = if (w >= waitLimit)
            (if (frozen) t.with("promptLeft", true).with("pc", DoneFail)
             else t.with("pc", GiveLook))
          else if (hung and hangApplies(st)) t.with("pc", GiveLook)
          else t
  }

  // A prompt that came up after the timer fired is the user's: back to waiting.
  pure def backToPrompt(s: State): bool = relook and promptFreeze and s.screen == Prompt

  action giveLook = all {
    st.pc == GiveLook,
    st' = if (relook and st.screen == Session) st.with("pc", DoneOk)
          else if (backToPrompt(st)) st.with("pc", Wait)
          else if (not(retryAndClean)) st.with("pc", DoneFail)
          else st.with("pc", GiveClear)
  }

  action giveClear = all {
    st.pc == GiveClear,
    val c = clearStuck(st)
    st' = if (relook and c.screen == Session) c.with("pc", DoneOk)
          else if (backToPrompt(c)) c.with("pc", Wait)
          else c.with("pc", GiveStop)
  }

  action giveStop = all { st.pc == GiveStop, st' = stopTunnel(st).with("pc", GiveSettle) }

  // A session window under the stopped tunnel turns into its dialog after the
  // stop; with waitOldGone the launcher waits for that, then clears again.
  action giveSettle = all {
    st.pc == GiveSettle,
    not(waitOldGone and st.screen == Dropping),
    val clean = if (waitOldGone) clearStuck(st) else st
    val timeLeft = not(oneDeadline and clean.elapsed >= deadline)
    st' = if (clean.attempt < maxAttempts and timeLeft) beginAttempt(clean, clean.attempt + 1)
          else clean.with("pc", DoneFail)
  }

  // --- the world ------------------------------------------------------

  action linkDown = all {
    not(done(st)), st.net == NetUp, st.faults < maxFaults,
    st' = fault(st).with("net", NetDown).with("tunnel", if (st.tunnel == Live) Stale else st.tunnel)
  }

  action linkUp = {
    nondet survives = Set(false, true).oneOf()
    all {
      not(done(st)), st.net == NetDown,
      st' = st.with("net", NetUp).with("tunnel", if (survives and st.tunnel == Stale) Live else st.tunnel)
    }
  }

  action serverChanges = {
    nondet newServer = Set(Ok, Stalls, Off).oneOf()
    all {
      not(done(st)), st.server != newServer, st.faults < maxFaults,
      st' = fault(st).with("server", newServer)
              .with("screen", if (newServer == Off and st.screen == Session) Dropping else st.screen)
    }
  }

  // ServerAliveInterval ends a stale ssh; its connection drops.
  action sshDies = all {
    not(done(st)), st.tunnel == Stale,
    st' = st.with("tunnel", NoTunnel)
            .with("screen", if (st.screen == Session) Dropping
                            else if (st.screen == Prompt) FailedDialog
                            else st.screen)
  }

  action dropShows = all { not(done(st)), st.screen == Dropping, st' = st.with("screen", FailedDialog) }

  action goSlow = all {
    not(done(st)), st.screen == Connecting, not(st.slow), st.waited == 0,
    st' = st.with("slow", true).with("everSlow", true)
  }

  action screenFinishes = all {
    not(done(st)), canFinish(st),
    st' = st.with("screen", if (not(working(st))) FailedDialog
                            else if (st.firstLaunch) Prompt
                            else Session)
  }

  action promptAnswered = all {
    not(done(st)), st.screen == Prompt, working(st),
    st' = st.with("screen", Session).with("firstLaunch", false)
  }

  // The user cancels this launch's connect.
  action userCancels = all {
    st.pc == Wait, st.screen == Connecting, not(st.userCancelled),
    st' = st.with("screen", Closed).with("userCancelled", true)
  }

  // Apalache and TLC report a run with no enabled action as a deadlock.
  action idle = all { done(st), st' = st }

  action step = any {
    start, probe, startSsh, checkNew, openLocation, seeSession, seeFailure,
    seeUserCancel, tick, giveLook, giveClear, giveStop, giveSettle,
    linkDown, linkUp, serverChanges, sshDies, dropShows, goSlow, screenFinishes,
    promptAnswered, userCancels, idle
  }

  // --- properties -----------------------------------------------------

  // A failed launch leaves no window to close and no ssh holding the port,
  // except an open password prompt the user is still to answer.
  val cleanFailure: bool =
    (st.pc == DoneFail and not(st.promptLeft)) implies
      (st.stuck == 0 and st.screen == Closed and st.tunnel == NoTunnel)

  // A launch that connected leaves no stray window from an earlier try.
  val cleanSuccess: bool = st.pc == DoneOk implies st.stuck == 0

  // A launch with the link up and the server answering throughout never
  // fails, unless it waits on the user's password or a connect took longer
  // than the deadline (A4).
  val noFailedHealthyLaunch: bool =
    (st.pc == DoneFail and st.launchHealthy and not(st.everSlow)) implies st.promptLeft

  // Success is a working session, when no fault hit this attempt. A remote
  // VNC daemon that hangs after its banner is excluded: its banner still
  // answers, so no probe of the banner can tell its frozen session from a
  // live one (accepted in the 2026-11-06 TRIAL).
  val successIsLive: bool =
    (st.pc == DoneOk and st.attemptFaults == 0 and st.server != Stalls) implies
      (st.screen == Session and working(st))

  // Cleanup never ends a working session or a password prompt.
  val noLiveSessionKilled: bool = st.liveSessionKills == 0
  val promptNeverKilled: bool = st.promptKills == 0

  // A connection the user cancelled is not opened again.
  val respectsUserCancel: bool = st.reopenedAfterCancel == 0

  val boundedAttempts: bool = st.attempt <= maxAttempts

  // The launch waits at most 30 s, password prompts excluded.
  val withinDeadline: bool = st.elapsed <= deadline
}

// main before 2026-11-06: port-listen check, no early exit, no cleanup, no retry.
module shareMain {
  import screenshare_connect(bannerProbe = false, retryAndClean = false, clearBeforeOpen = false,
    relook = false, reprobe = false, waitOldGone = false, promptFreeze = false,
    userCancelExits = false, oneDeadline = false).*
}

// The design as first written on 2026-11-06: banner probe, retry and cleanup.
module shareProposed {
  import screenshare_connect(bannerProbe = true, retryAndClean = true, clearBeforeOpen = false,
    relook = false, reprobe = false, waitOldGone = false, promptFreeze = false,
    userCancelExits = false, oneDeadline = false).*
}

// The design after the 2026-11-06 TRIAL: every fix on.
module shareFinal {
  import screenshare_connect(bannerProbe = true, retryAndClean = true, clearBeforeOpen = true,
    relook = true, reprobe = true, waitOldGone = true, promptFreeze = true,
    userCancelExits = true, oneDeadline = true).*
}
