// AugustUnlock: a widget tap sends its command over Bluetooth and the cloud
// at the same moment (Amit, 2026-11-09; BothPaths.run, ParallelPaths).
// When Bluetooth moves the door first, August still holds the same command
// and nothing can recall it. One door, the widget's unlock button and Lock
// Both. The command holds the lock's gate until August answers, the tap's
// deadline cuts it off, or the process dies with the command still out.
//
// lockedIsTrue: when the center button says "Locked", the door is locked and
// August holds no unlock that can open it afterwards.
// `pathsDraft` is the design before its TRIAL (the "an unlock may still
// land" mark written when the wait for August ends): a dead process never
// writes it. `pathsOneMark` writes it at the Bluetooth win but keeps one mark
// per door: a newer tap's reply clears an older unlock still out.
// `pathsNoRunning` ignores a tap with no end: the cloud unlock goes out when
// the tap starts, so a process that dies before any answer leaves an unlock
// out and no mark (found by the pre-push review, 2026-11-09).
// `pathsShipped` is the code (DoorState.tails and DoorState.running beside
// DoorState.unanswered).
// August runs held commands in any order. The marks never expire here; the
// app's last 60 s (DoorState.unansweredWindow), so a command August holds
// longer than that is not covered, as in ghost_order.qnt.
//
// max-steps: 16
// verify: search-only  (a list of held commands; not yet sized for Apalache in CI)
module widget_paths {
  // The mark is written at the Bluetooth win, before the tap returns.
  const markAtWin: bool
  // An older unanswered mark survives a newer tap's reply.
  const keepOlderMark: bool
  // An unlock tap with no end counts as an unlock that may still land.
  const countRunning: bool

  type Phase = Idle | Both | Tail
  type Center = CNone | CLocked | CNoReply
  type Cmd = { unlock: bool, id: int }

  type S = {
    open: bool,            // the real door
    august: List[Cmd],     // commands August still holds
    phase: Phase,          // the command that holds the gate
    unlock: bool,
    cur: int,
    next: int,
    tail: int,             // DoorState.tails: the unlock still out, or -1
    tapOpen: bool,         // DoorState.running: an unlock tap with no end yet
    unanswered: bool,      // DoorState.unanswered, inside its window
    center: Center
  }
  var st: S

  action init = st' = {
    open: false, august: List(), phase: Idle, unlock: true, cur: -1, next: 0,
    tail: -1, tapOpen: false, unanswered: false, center: CNone
  }

  // DoorState.recordLocks: "Locked" unless an unlock may still land.
  pure def lockResult(s: S): Center =
    if (s.unanswered or s.tail != -1 or (countRunning and s.tapOpen)) CNoReply else CLocked

  pure def start(s: S, unlock: bool): S =
    s.with("phase", Both).with("unlock", unlock).with("cur", s.next).with("next", s.next + 1)
     .with("august", s.august.append({ unlock: unlock, id: s.next }))

  // A tap waits at the gate, so it starts only when no command holds it.
  // DoorState.start: a tap left open by a dead process becomes an unanswered unlock.
  action tapUnlock = all {
    st.phase == Idle,
    st' = start(st, true).with("center", CNone).with("tapOpen", true)
            .with("unanswered", st.unanswered or (countRunning and st.tapOpen))
  }
  action tapLockBoth = all { st.phase == Idle, st' = start(st, false) }

  // Bluetooth moves the door first: the tap is answered, August's copy is still out.
  action bluetoothWins = all {
    st.phase == Both,
    val moved = st.with("open", st.unlock).with("phase", Tail)
    st' = if (st.unlock)
            if (markAtWin) moved.with("tapOpen", false).with("tail", st.cur)
                                .with("unanswered", st.unanswered or (keepOlderMark and st.tail != -1))
            else moved.with("tapOpen", false)
          else moved.with("center", lockResult(st))
  }

  // August runs one held command, in any order.
  action augustRuns = all {
    st.august.length() > 0,
    nondet i = oneOf(0.to(st.august.length() - 1))
    val h = st.august[i]
    val rest = st.august.slice(0, i).concat(st.august.slice(i + 1, st.august.length()))
    val ran = st.with("open", h.unlock).with("august", rest)
    val mine = h.id == st.cur
    st' = if (mine and st.phase == Both)
            // The cloud answers the tap.
            if (h.unlock) ran.with("phase", Idle).with("tapOpen", false) else ran.with("phase", Idle).with("center", lockResult(st))
          else if (mine and st.phase == Tail)
            // August's reply after a Bluetooth win: DoorState.tailConfirmed.
            ran.with("phase", Idle).with("tail", if (h.unlock and st.tail == st.cur) -1 else st.tail)
          else ran
  }

  // The tap's deadline before any answer: DoorState.finish marks an unlock unanswered.
  action deadlineBeforeAnswer = all {
    st.phase == Both,
    st' = if (st.unlock) st.with("phase", Idle).with("unanswered", true).with("tapOpen", false)
          else st.with("phase", Idle).with("center", CNoReply)
  }
  // The process dies before any answer: nothing is written, the tap stays open.
  action processDiesBeforeAnswer = all { st.phase == Both, st' = st.with("phase", Idle) }
  // The deadline with August's copy still out, in a live process.
  action deadlineInTail = all {
    st.phase == Tail,
    st' = st.with("phase", Idle).with("unanswered", st.unanswered or (not(markAtWin) and st.unlock))
  }
  // iOS suspends or ends the process with August's copy still out: nothing is written.
  action processDiesInTail = all { st.phase == Tail, st' = st.with("phase", Idle) }

  action step = any {
    tapUnlock, tapLockBoth, bluetoothWins, augustRuns, deadlineBeforeAnswer, processDiesBeforeAnswer, deadlineInTail, processDiesInTail
  }

  val unlockHeld: bool = st.august.indices().exists(i => st.august[i].unlock)
  val lockedIsTrue: bool = st.center != CLocked or (not(st.open) and not(unlockHeld))
}

module pathsDraft     { import widget_paths(markAtWin = false, keepOlderMark = false, countRunning = true).* }
module pathsOneMark   { import widget_paths(markAtWin = true,  keepOlderMark = false, countRunning = true).* }
module pathsNoRunning { import widget_paths(markAtWin = true,  keepOlderMark = true,  countRunning = false).* }
module pathsShipped   { import widget_paths(markAtWin = true,  keepOlderMark = true,  countRunning = true).* }
