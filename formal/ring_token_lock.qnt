// Ring refresh-token rotation, shared by RingSecurity and RingBeams.
//
// Ring OAuth rotates the refresh token on every use, so two actors that each
// read the token file and then refresh will race: the loser gets
// `invalid_grant`. The jobs are serialized by an flock (lib/file_lock.py).
// This model asks: when is that serialization actually airtight?
//
// Actors (one run each; the question is mutual exclusion, not throughput):
//   rs  RingSecurity            RingSecurity/ring_manager.py check
//   bp  RingBeams parent        RingBeams/beams_manager.py check
//   sc  RingBeams Node sidecar  spawned by bp, refreshes the token itself
//   au  interactive login       RingSecurity/ring_manager.py auth
//
// Two switches select the code under test; each instance below fixes them.
//
// ASSUMPTION A1: a fresh login (au) invalidates the refresh token Ring handed
//   out before it. Not confirmed against Ring's server. If false, the au
//   counterexamples below are benign and only the sidecar one stands.
// Out of scope: crashes between "server rotated" and "file written" lose the
//   token regardless of locking; a hung sidecar (see RingBeams/watchdog.js).

module ring_token_lock {
  // lib/file_lock.py yields the lock fd and run_sidecar passes it to the
  // sidecar via pass_fds, so the lock lives as long as any inheritor.
  const childInheritsLock: bool
  // `ring_manager.py auth` runs inside acquire_lock.
  const authTakesLock: bool

  type RsPc = RsIdle | RsLocked | RsRead | RsRotated | RsDone | RsFailed
  type BpPc = BpIdle | BpLocked | BpSpawned | BpDone | BpDead
  type ScPc = ScNone | ScStarted | ScRead | ScRotated | ScDone | ScFailed
  type AuPc = AuIdle | AuLoggedIn | AuDone

  type State = {
    rs: RsPc,
    bp: BpPc,
    sc: ScPc,
    au: AuPc,
    // Open file descriptions on <token>.lock. flock is held iff non-empty:
    // it is released when the LAST holder closes, never per process.
    holders: Set[str],
    serverGen: int,  // generation of the refresh token Ring will accept
    fileGen: int,    // generation currently in the token file
    rsTok: int,      // token in each actor's hand
    scTok: int,
    auTok: int,
    invalidGrants: int
  }

  var st: State

  action init = st' = {
    rs: RsIdle, bp: BpIdle, sc: ScNone, au: AuIdle,
    holders: Set(), serverGen: 0, fileGen: 0,
    rsTok: -1, scTok: -1, auTok: -1, invalidGrants: 0
  }

  pure def lockFree(s: State): bool = s.holders.size() == 0
  pure def add(s: State, who: str): Set[str] = s.holders.union(Set(who))
  pure def drop(s: State, who: str): Set[str] = s.holders.exclude(Set(who))

  // ---- RingSecurity: holds the lock for its whole run ----
  action rsAcquire = all {
    st.rs == RsIdle, lockFree(st),
    st' = { ...st, rs: RsLocked, holders: add(st, "rs") },
  }
  action rsRead = all {
    st.rs == RsLocked,
    st' = { ...st, rs: RsRead, rsTok: st.fileGen },
  }
  action rsRefresh = all {
    st.rs == RsRead,
    if (st.rsTok == st.serverGen)
      st' = { ...st, rs: RsRotated, serverGen: st.serverGen + 1, rsTok: st.serverGen + 1 }
    else
      st' = { ...st, rs: RsFailed, invalidGrants: st.invalidGrants + 1, holders: drop(st, "rs") },
  }
  action rsWrite = all {
    st.rs == RsRotated,
    st' = { ...st, rs: RsDone, fileGen: st.rsTok, holders: drop(st, "rs") },
  }

  // ---- RingBeams parent: holds the lock across the sidecar ----
  action bpAcquire = all {
    st.bp == BpIdle, lockFree(st),
    st' = { ...st, bp: BpLocked, holders: add(st, "bp") },
  }
  action bpSpawn = all {
    st.bp == BpLocked,
    st' = { ...st, bp: BpSpawned, sc: ScStarted,
            holders: if (childInheritsLock) add(st, "sc") else st.holders },
  }
  action bpReap = all {
    st.bp == BpSpawned, st.sc == ScDone or st.sc == ScFailed,
    st' = { ...st, bp: BpDone, holders: drop(st, "bp") },
  }
  // SIGKILL / OOM: the kernel closes bp's fds; a spawned sidecar lives on.
  action bpKill = all {
    st.bp == BpLocked or st.bp == BpSpawned,
    st' = { ...st, bp: BpDead, holders: drop(st, "bp") },
  }

  // ---- Node sidecar ----
  action scRead = all {
    st.sc == ScStarted,
    st' = { ...st, sc: ScRead, scTok: st.fileGen },
  }
  action scRefresh = all {
    st.sc == ScRead,
    if (st.scTok == st.serverGen)
      st' = { ...st, sc: ScRotated, serverGen: st.serverGen + 1, scTok: st.serverGen + 1 }
    else
      st' = { ...st, sc: ScFailed, invalidGrants: st.invalidGrants + 1, holders: drop(st, "sc") },
  }
  action scWrite = all {
    st.sc == ScRotated,
    st' = { ...st, sc: ScDone, fileGen: st.scTok, holders: drop(st, "sc") },
  }

  // ---- Interactive login ----
  action auLogin = all {
    st.au == AuIdle,
    authTakesLock implies lockFree(st),
    st' = { ...st, au: AuLoggedIn, serverGen: st.serverGen + 1, auTok: st.serverGen + 1,
            holders: if (authTakesLock) add(st, "au") else st.holders },
  }
  action auWrite = all {
    st.au == AuLoggedIn,
    st' = { ...st, au: AuDone, fileGen: st.auTok, holders: drop(st, "au") },
  }

  // Every actor has run to completion (or died). Quint's `verify` reports
  // "no enabled action" as a deadlock, so the finished state idles explicitly:
  // a state that is stuck BEFORE this point is still reported as a deadlock.
  val terminal: bool =
    (st.rs == RsDone or st.rs == RsFailed) and
    (st.bp == BpDone or st.bp == BpDead) and
    (st.sc == ScNone or st.sc == ScDone or st.sc == ScFailed) and
    st.au == AuDone
  action idle = all { terminal, st' = st }

  action step = any {
    rsAcquire, rsRead, rsRefresh, rsWrite,
    bpAcquire, bpSpawn, bpReap, bpKill,
    scRead, scRefresh, scWrite,
    auLogin, auWrite,
    idle,
  }

  // ---- Properties ----
  // A "writer in flight" holds a token it read or minted and has yet to store.
  val inFlight: Set[str] = Set(
    if (st.rs == RsRead or st.rs == RsRotated) "rs" else "",
    if (st.sc == ScRead or st.sc == ScRotated) "sc" else "",
    if (st.au == AuLoggedIn) "au" else "",
  ).exclude(Set(""))

  // At most one token writer between read and store.
  val mutualExclusion: bool = inFlight.size() <= 1
  // The same, over the two lock-using writers only. Isolates the sidecar
  // orphan from the unlocked `auth` path.
  val lockedWritersExclusive: bool = not(inFlight.contains("rs") and inFlight.contains("sc"))
  // The consequence that pages us: nobody presented a rotated-away token.
  val noInvalidGrant: bool = st.invalidGrants == 0
  val safe: bool = mutualExclusion and noInvalidGrant
}

// Code as of main before this change: sidecar does not inherit the lock.
module current {
  import ring_token_lock(childInheritsLock = false, authTakesLock = false).*
}

// This change: the sidecar inherits the lock. `auth` is still unlocked.
module orphanFixed {
  import ring_token_lock(childInheritsLock = true, authTakesLock = false).*
}

// What taking the lock in `auth` as well would give.
module allFixed {
  import ring_token_lock(childInheritsLock = true, authTakesLock = true).*
}
