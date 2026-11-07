-- Opens a saved Screen Sharing connection in full screen, then fits it to the screen.
-- Template: build_app.py replaces the placeholders with AppleScript literals.
use framework "AppKit"
use scripting additions

property connectionURL : __URL__
property windowTitle : __TITLE__
property tunnelCommand : __TUNNEL__ -- empty: connect directly
property stopCommand : __STOP__ -- empty: no tunnel to stop
property fallbackApp : __FALLBACK__ -- empty: no other app to offer
property waitSeconds : __WAIT__ -- a password prompt may stay open this long
property deadlineSeconds : __DEADLINE__ -- the whole launch, password prompts excluded
property maxAttempts : 3
property retryDelay : 5
property minAttemptSeconds : 10 -- a cold Screen Sharing takes seconds to show anything
property waitPoll : 0.5
property goneSeconds : 2 -- a Connecting window gone this long, with nothing in its place: the user cancelled
property settleSeconds : 3 -- an old session window turns into its alert after its tunnel stops
property screenSharingID : "com.apple.ScreenSharing"
property maxZoomSteps : 8 -- stop even if the picture never overflows
property pollSeconds : 0.05
property resizeTimeout : 2 -- Actual Size on a remote as large as this screen does not resize
property drawSeconds : 0.3 -- after a resize or zoom; the scroll bars update within 0.15 s
property gap : 24 -- between the permission windows and the screen edges
property permissionPane : "x-apple.systempreferences:com.apple.settings.PrivacySecurity.extension?Privacy_Accessibility"

-- The state machine is formal/screenshare_connect.qnt (shareFinal), proved with TLC.
on run
	try
		my requireAccessibility()
		set clock to {startedAt:my now(), promptTime:0}
		my clearStuck()
		set reason to ""
		repeat with attempt from 1 to maxAttempts
			set {outcome, reason} to my attemptOnce(clock)
			if outcome is "session" then
				my showSession()
				return
			end if
			if outcome is "cancelled" then return
			if outcome is not "failed" then exit repeat
			if (my elapsed(clock)) + retryDelay + minAttemptSeconds > deadlineSeconds then exit repeat
			delay retryDelay
		end repeat
		my offerFallback(reason)
	on error errText number errNum
		-- -1719 and -25211: System Events refused because this app lacks Accessibility.
		if errNum is in {-1719, -25211} then
			my askForPermission(errText)
		else
			display dialog (name of me) & ": " & errText buttons {"OK"} default button 1 with icon stop
		end if
	end try
end run

-- One connect. Returns {outcome, reason}: "session", "cancelled", "failed" (cleaned up, may
-- retry), "promptTimeout" or "timeout" (left as is: the window is the user's).
on attemptOnce(clock)
	try
		set tunnelState to my openTunnel()
	on error errText
		set cleanup to my giveUp()
		if cleanup is "session" then return {"session", ""}
		if cleanup is "prompt" then return my waitForOutcome(clock)
		return {"failed", "The SSH tunnel failed. " & errText}
	end try
	-- A window with the session's title after a new tunnel belongs to the old, dead one.
	if tunnelState is "started" then my waitOldGone()
	my clearStuck()
	-- The URL is the saved connection's own address and user, so Screen Sharing reuses it.
	open location connectionURL
	my bringForward()
	return my waitForOutcome(clock)
end attemptOnce

-- Polls Screen Sharing until the connect ends; cleans up a failed or hung one.
on waitForOutcome(clock)
	set lastPoll to my now()
	set promptSince to missing value
	set lastBusy to missing value
	repeat
		set snap to my snapshot()
		set t to my now()
		if hasPrompt of snap then set promptTime of clock to (promptTime of clock) + (t - lastPoll)
		set lastPoll to t
		if not (hasPrompt of snap) then
			set promptSince to missing value
		else if promptSince is missing value then
			set promptSince to t
		end if
		if promptSince is missing value then
			set promptFor to 0
		else
			set promptFor to t - promptSince
		end if
		-- A prompt counts too: after the password, the prompt goes before the session shows.
		if hasBusy of snap or hasPrompt of snap then set lastBusy to t
		if lastBusy is missing value then
			set goneFor to 0
		else
			set goneFor to t - lastBusy
		end if
		set nextStep to my decide(snap, my elapsed(clock), promptFor, goneFor)
		if nextStep is "session" then return {"session", ""}
		if nextStep is "cancelled" then return {"cancelled", ""}
		if nextStep is "promptTimeout" then return {"promptTimeout", "The password prompt is still open after " & waitSeconds & " seconds."}
		if nextStep is "timeout" then return {"timeout", "No session after " & deadlineSeconds & " seconds."}
		if nextStep is in {"failed", "hung"} then
			set cleanup to my giveUp()
			if cleanup is "session" then return {"session", ""}
			if cleanup is not "prompt" then
				if nextStep is "failed" then return {"failed", "Screen Sharing could not connect."}
				return {"failed", "Screen Sharing hung on Connecting for " & deadlineSeconds & " seconds."}
			end if
		end if
		delay waitPoll
	end repeat
end waitForOutcome

-- What the wait does next. Pure, so tests run it with made-up snapshots.
-- launchSeconds: launch time outside password prompts. promptFor: how long the prompt has been
-- open. goneFor: seconds since
-- this connect's Connecting window was last seen (0: never seen).
on decide(snap, launchSeconds, promptFor, goneFor)
	if hasSession of snap then return "session"
	if hasPrompt of snap then
		if promptFor ≥ waitSeconds then return "promptTimeout"
		return "wait"
	end if
	if hasFailed of snap then return "failed"
	if hasBusy of snap then
		if launchSeconds ≥ deadlineSeconds then return "hung"
		return "wait"
	end if
	-- No window can also mean they are on another Space; Cancel quits Screen Sharing.
	if goneFor ≥ goneSeconds and not (offSpace of snap) then return "cancelled"
	if launchSeconds ≥ deadlineSeconds then return "timeout"
	return "wait"
end decide

-- Throws -1719 or -25211 without Accessibility, so no session starts that the app cannot fit.
on requireAccessibility()
	tell application "System Events" to count UI elements of process "Dock"
end requireAccessibility

-- "reused", "started" or "direct". Throws ssh's error, or why the far end did not answer.
on openTunnel()
	if tunnelCommand is "" then return "direct"
	return do shell script tunnelCommand
end openTunnel

on stopTunnel()
	if stopCommand is "" then return
	try
		do shell script stopCommand
	end try
end stopTunnel

-- After a failed or hung connect: look for a session or a password prompt that came up late,
-- clear, look again, then stop the tunnel. Returns "session", "prompt" or "clean".
on giveUp()
	repeat 2 times
		set snap to my snapshot()
		if hasSession of snap then return "session"
		if hasPrompt of snap then return "prompt"
		my clearStuck()
	end repeat
	my stopTunnel()
	my waitOldGone()
	return "clean"
end giveUp

-- A session window whose tunnel stopped keeps its title for a moment, then shows an alert.
-- Wait for that, clear it, and close a window that is still there.
on waitOldGone()
	set t0 to my now()
	repeat while (my now()) - t0 < settleSeconds
		if not (hasSession of (my snapshot())) then exit repeat
		delay 0.2
	end repeat
	my clearStuck()
	if not (my screenSharingRunning()) then return
	try
		tell application "System Events" to tell process "Screen Sharing"
			repeat with w in (every window whose name is windowTitle)
				click (first button of w whose subrole is "AXCloseButton")
			end repeat
		end tell
	end try
end waitOldGone

-- Click Cancel on every Connecting window and the only button of every failure alert. Never
-- touches a password prompt or a session.
on clearStuck()
	if not (my screenSharingRunning()) then return
	try
		tell application "System Events" to set wins to every window of process "Screen Sharing"
	on error
		return
	end try
	repeat with w in wins
		try
			set winKind to my classify(my windowInfo(w))
			tell application "System Events"
				if winKind is "busy" then click button 1 of w
				if winKind is "failed" then
					if exists sheet 1 of w then
						click button 1 of sheet 1 of w
					else
						click button 1 of w
					end if
				end if
			end tell
		end try
	end repeat
end clearStuck

-- What Screen Sharing shows now, as booleans. A window that closes while it is read makes
-- the pass partial, which could hide a session from cleanup: read again, up to 3 times.
on snapshot()
	repeat 3 times
		set {snap, complete} to my readWindows()
		if complete then exit repeat
		delay 0.2
	end repeat
	return snap
end snapshot

on readWindows()
	set snap to {isRunning:false, offSpace:false, hasSession:false, hasPrompt:false, hasFailed:false, hasBusy:false}
	if not (my screenSharingRunning()) then return {snap, true}
	set isRunning of snap to true
	try
		tell application "System Events" to set wins to every window of process "Screen Sharing"
	on error
		return {snap, false}
	end try
	if (count of wins) is 0 then
		-- Its windows are on another Space until it is in front.
		set offSpace of snap to true
		my bringForward()
		return {snap, true}
	end if
	set complete to true
	repeat with w in wins
		try
			set winKind to my classify(my windowInfo(w))
			if winKind is "session" then set hasSession of snap to true
			if winKind is "prompt" then set hasPrompt of snap to true
			if winKind is "failed" then set hasFailed of snap to true
			if winKind is "busy" then set hasBusy of snap to true
		on error
			set complete to false
		end try
	end repeat
	return {snap, complete}
end readWindows

-- Matched by shape, not by English text. Pure, so tests run it with made-up windows.
on classify(info)
	if hasField of info then return "prompt"
	if sheetButtons of info is 1 then return "failed" -- an alert on a session window
	if sheetButtons of info > 1 then return "other"
	if winTitle of info is windowTitle then return "session"
	if hasBusy of info and buttonCount of info is 1 then return "busy"
	if winSubrole of info is "AXDialog" and buttonCount of info is 1 then return "failed"
	return "other"
end classify

on windowInfo(w)
	tell application "System Events"
		set t to name of w
		if t is missing value then set t to ""
		set r to subrole of w
		if r is missing value then set r to ""
		set sheetCount to 0
		set fieldFound to exists text field 1 of w
		if exists sheet 1 of w then
			set sheetCount to count of buttons of sheet 1 of w
			if not fieldFound then set fieldFound to exists text field 1 of sheet 1 of w
		end if
		return {winTitle:t, winSubrole:r, hasBusy:(exists busy indicator 1 of w), buttonCount:(count of buttons of w), hasField:fieldFound, sheetButtons:sheetCount}
	end tell
end windowInfo

-- NSRunningApplication answers at once; System Events takes 2.4 s when the app is not running.
on screenSharingRunning()
	return (count of (current application's NSRunningApplication's runningApplicationsWithBundleIdentifier:screenSharingID)) > 0
end screenSharingRunning

-- Activates Screen Sharing only if it runs: telling it to activate would launch it.
on bringForward()
	set apps to current application's NSRunningApplication's runningApplicationsWithBundleIdentifier:screenSharingID
	if (count of apps) > 0 then (item 1 of apps)'s activateWithOptions:0
end bringForward

on now()
	return (current application's NSDate's timeIntervalSinceReferenceDate()) as real
end now

on elapsed(clock)
	return (my now()) - (startedAt of clock) - (promptTime of clock)
end elapsed

-- Says why the connection failed, and offers fallbackApp when there is one.
on offerFallback(reason)
	set appName to name of me
	activate
	if fallbackApp is "" then
		display dialog appName & ": " & reason buttons {"OK"} default button 1 with icon stop
		return
	end if
	set openLabel to "Open " & fallbackApp
	set answer to button returned of (display dialog appName & ": " & reason & return & return & ¬
		openLabel & " instead?" buttons {"Not Now", openLabel} default button 2 with icon caution)
	if answer is openLabel then do shell script "open -a " & quoted form of fallbackApp
end offerFallback

-- Saved connections open in a window titled with the connection's name.
on showSession()
	tell application "System Events" to tell process "Screen Sharing"
		set sessionWindow to first window whose name is windowTitle
		set frontmost to true
		perform action "AXRaise" of sessionWindow
		-- A new session opens windowed. Full screen means it was already up: just switch.
		if value of attribute "AXFullScreen" of sessionWindow then return
		set oldSize to size of sessionWindow
		set value of attribute "AXFullScreen" of sessionWindow to true
		my waitForResize(sessionWindow, oldSize)
		my fitPicture(it, sessionWindow)
	end tell
end showSession

-- Largest zoom with no scroll bar on either axis. Scaling only shrinks, so a remote smaller
-- than this screen needs zoom to fill it; a larger one needs scaling.
on fitPicture(proc, sessionWindow)
	tell application "System Events" to set oldSize to size of sessionWindow
	my viewMenuClick(proc, "Actual Size")
	my waitForResize(sessionWindow, oldSize)
	if my overflows(sessionWindow) then
		my viewMenuClick(proc, "Turn Scaling On")
		return
	end if
	repeat maxZoomSteps times
		my viewMenuClick(proc, "Zoom In")
		if my overflows(sessionWindow) then
			my viewMenuClick(proc, "Zoom Out")
			return
		end if
	end repeat
end fitPicture

-- A click before the last one has drawn stacks on it, so every click waits.
on viewMenuClick(proc, itemName)
	tell application "System Events" to tell menu "View" of menu bar 1 of proc
		if exists menu item itemName then click menu item itemName
	end tell
	delay drawSeconds
end viewMenuClick

-- Full screen and Actual Size resize the window after a delay (0.8 s and 0.5 s measured).
-- During full screen the window is briefly unreadable, hence the try.
on waitForResize(sessionWindow, oldSize)
	repeat (resizeTimeout / pollSeconds) times
		try
			tell application "System Events" to if size of sessionWindow is not oldSize then exit repeat
		end try
		delay pollSeconds
	end repeat
	delay drawSeconds
end waitForResize

-- The shared screen gets scroll bars only while the picture is larger than the window.
on overflows(sessionWindow)
	tell application "System Events"
		return exists scroll bar 1 of (first UI element of sessionWindow whose role is "AXSharedScreen")
	end tell
end overflows

-- Without Accessibility permission, System Events refuses. Show the list and this app side by
-- side, then the steps on top of both.
on askForPermission(errText)
	set appName to name of me
	do shell script "open -R " & quoted form of POSIX path of (path to me)
	open location permissionPane
	try
		my placeSideBySide()
	end try
	activate
	display dialog appName & " needs Accessibility permission to set full screen. It did not connect." & return & return & ¬
		"1. If " & appName & " is already in the list, select it and click − to remove it. " & ¬
		"Each rebuild makes the old entry stale, even when it shows as on." & return & ¬
		"2. Drag " & appName & " from Finder into the list and turn it on." & return & ¬
		"3. Open " & appName & " again." & return & return & ¬
		"(" & errText & ")" buttons {"OK"} default button 1 with icon caution
end askForPermission

-- System Settings on the left, Finder on the right, centered on the main screen. Uses each
-- app's own scripting, not Accessibility, which this app does not have yet.
on placeSideBySide()
	tell application "System Settings"
		repeat 40 times
			if exists window 1 then exit repeat
			delay 0.1
		end repeat
	end tell
	set {x0, y0, areaW, areaH} to my usableArea()
	set paneW to (areaW - 3 * gap) div 2
	if paneW > 900 then set paneW to 900
	set paneH to areaH - 2 * gap
	if paneH > 1000 then set paneH to 1000
	set y1 to y0 + gap
	tell application "System Settings"
		-- It caps its own width, so measure it, then center the pair.
		set bounds of window 1 to {x0, y1, x0 + paneW, y1 + paneH}
		set settingsW to (item 3 of (get bounds of window 1)) - x0
		set x1 to x0 + (areaW - settingsW - gap - paneW) div 2
		set bounds of window 1 to {x1, y1, x1 + settingsW, y1 + paneH}
		activate
	end tell
	set x2 to x1 + settingsW + gap
	tell application "Finder"
		set bounds of Finder window 1 to {x2, y1, x2 + paneW, y1 + paneH}
		activate
	end tell
end placeSideBySide

-- The main screen without the menu bar and Dock, in top-left window coordinates.
on usableArea()
	set mainScreen to current application's NSScreen's mainScreen()
	set screenH to item 2 of item 2 of (mainScreen's frame() as list)
	set {{vx, vy}, {vw, vh}} to mainScreen's visibleFrame() as list
	return {vx as integer, (screenH - vy - vh) as integer, vw as integer, vh as integer}
end usableArea
