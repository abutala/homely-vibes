-- Opens a saved Screen Sharing connection in full screen, then fits it to the screen.
-- Template: build_app.py replaces the placeholders with AppleScript literals.
use framework "AppKit"
use scripting additions

property connectionURL : __URL__
property windowTitle : __TITLE__
property waitSeconds : 90
property maxZoomSteps : 8 -- stop even if the picture never overflows
property pollSeconds : 0.05
property resizeTimeout : 2 -- Actual Size on a remote as large as this screen does not resize
property drawSeconds : 0.3 -- after a resize or zoom; the scroll bars update within 0.15 s
property gap : 24 -- between the permission windows and the screen edges
property permissionPane : "x-apple.systempreferences:com.apple.settings.PrivacySecurity.extension?Privacy_Accessibility"

on run
	try
		my requireAccessibility()
		-- The URL is the saved connection's own address and user, so Screen Sharing reuses it.
		open location connectionURL
		set sessionWindow to my waitForSessionWindow()
		if sessionWindow is missing value then return
		tell application "System Events" to tell process "Screen Sharing"
			set frontmost to true
			perform action "AXRaise" of sessionWindow
			-- A new session opens windowed. Full screen means it was already up: just switch.
			if value of attribute "AXFullScreen" of sessionWindow then return
			set oldSize to size of sessionWindow
			set value of attribute "AXFullScreen" of sessionWindow to true
			my waitForResize(sessionWindow, oldSize)
			my fitPicture(it, sessionWindow)
		end tell
	on error errText number errNum
		-- -1719 and -25211: System Events refused because this app lacks Accessibility.
		if errNum is in {-1719, -25211} then
			my askForPermission(errText)
		else
			display dialog (name of me) & ": " & errText buttons {"OK"} default button 1 with icon stop
		end if
	end try
end run

-- Throws -1719 or -25211 without Accessibility, so no session starts that the app cannot fit.
on requireAccessibility()
	tell application "System Events" to count UI elements of process "Dock"
end requireAccessibility

-- Saved connections open in a window titled with the connection's name.
on waitForSessionWindow()
	repeat (waitSeconds * 2) times
		tell application "System Events"
			if exists process "Screen Sharing" then
				if exists (first window of process "Screen Sharing" whose name is windowTitle) then
					return first window of process "Screen Sharing" whose name is windowTitle
				end if
			end if
		end tell
		delay 0.5
	end repeat
	return missing value
end waitForSessionWindow

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
