// AugustUnlock: CommandGate (AugustUnlock/CommandGate.swift), one per lock,
// at the grain of its lock blocks. Three tasks (a screen command, a widget
// tap, a second screen command) enter, wait, cancel and leave. The gate is
// never held without a holder, a free gate has no waiters, and a task
// cancelled while queued drops itself, which needs the post-queue check:
// `gateNoPostCheck` removes that line and leaks (the 2026-11-05 stress run
// found 38 of 300 before the fix).
//
// max-steps: 25
module gate {
  // true = the code as shipped: after queueing, a task that was already cancelled drops itself
  // (CommandGate.swift: `if Task.isCancelled { dropWaiter(id)... }`). false = that line removed.
  const postCheck: bool

  type Phase = Idle | Claimed | Queued | Holding | Done | Cancelled
  val tasks: Set[int] = Set(0, 1, 2)

  var busy: bool
  var waiters: List[int]
  var phase: int -> Phase
  var cancelled: int -> bool
  var chk: int -> bool       // the post-queue cancel check is still to run

  action init = all {
    busy' = false, waiters' = List(),
    phase' = tasks.mapBy(t => Idle), cancelled' = tasks.mapBy(t => false), chk' = tasks.mapBy(t => false),
  }

  // `enter`, first lock block: take the gate, or get an id.
  action claim(t: int): bool = all {
    phase.get(t) == Idle,
    busy' = true,
    phase' = phase.set(t, if (busy) Claimed else Holding),
    waiters' = waiters, cancelled' = cancelled, chk' = chk,
  }

  // Second lock block (inside the continuation): queue, or take a gate freed since.
  action queueUp(t: int): bool = all {
    phase.get(t) == Claimed,
    if (busy) all {
      waiters' = waiters.append(t), phase' = phase.set(t, Queued), busy' = busy,
      chk' = chk.set(t, postCheck and cancelled.get(t)),
    } else all {
      busy' = true, phase' = phase.set(t, Holding), waiters' = waiters, chk' = chk,
    },
    cancelled' = cancelled,
  }

  // The post-queue check: a cancel that came before the waiter was queued.
  action postCheckRuns(t: int): bool = all {
    chk.get(t), phase.get(t) == Queued,
    waiters' = waiters.select(w => w != t), phase' = phase.set(t, Cancelled), chk' = chk.set(t, false),
    busy' = busy, cancelled' = cancelled,
  }
  // If a hand-over won the race, the check finds no waiter and does nothing.
  action postCheckMisses(t: int): bool = all {
    chk.get(t), phase.get(t) != Queued,
    chk' = chk.set(t, false), waiters' = waiters, phase' = phase, busy' = busy, cancelled' = cancelled,
  }

  // `onCancel`: drops the waiter if it is queued, else only sets the flag.
  action cancel(t: int): bool = all {
    not(cancelled.get(t)), phase.get(t) != Done, phase.get(t) != Cancelled,
    cancelled' = cancelled.set(t, true),
    waiters' = waiters.select(w => w != t),
    phase' = if (phase.get(t) == Queued) phase.set(t, Cancelled) else phase,
    busy' = busy, chk' = chk,
  }

  // `leave`: hand the gate on, or free it.
  action leave(t: int): bool = all {
    phase.get(t) == Holding,
    if (waiters.length() == 0) all {
      busy' = false, waiters' = waiters, phase' = phase.set(t, Done),
    } else all {
      busy' = true, waiters' = waiters.tail(),
      phase' = phase.set(t, Done).set(waiters.head(), Holding),
    },
    cancelled' = cancelled, chk' = chk,
  }

  action step = any {
    all { nondet t = tasks.oneOf(); claim(t) },
    all { nondet t = tasks.oneOf(); queueUp(t) },
    all { nondet t = tasks.oneOf(); postCheckRuns(t) },
    all { nondet t = tasks.oneOf(); postCheckMisses(t) },
    all { nondet t = tasks.oneOf(); cancel(t) },
    all { nondet t = tasks.oneOf(); leave(t) },
  }

  // Never held forever: a busy gate has a holder who will leave.
  val busyHasHolder: bool = not(busy) or tasks.exists(t => phase.get(t) == Holding)
  // A free gate has nobody waiting.
  val freeMeansNoWaiters: bool = busy or waiters.length() == 0
  // Every queued task is a waiter and every waiter is queued.
  val queueConsistent: bool = tasks.forall(t => (phase.get(t) == Queued) == (waiters.select(w => w == t).length() > 0))
  // A queued task that was cancelled is about to drop itself: it never waits out the holder.
  val cancelledWaiterDrops: bool = tasks.forall(t => not(phase.get(t) == Queued and cancelled.get(t)) or chk.get(t))
}
module gateShipped { import gate(postCheck = true).* }
module gateNoPostCheck { import gate(postCheck = false).* }
