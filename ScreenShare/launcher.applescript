-- Opens a saved Screen Sharing connection in full screen, then fits it to the screen.
-- Template: build_app.py replaces the placeholders with AppleScript literals.
property connectionURL : __URL__
property windowTitle : __TITLE__
property waitSeconds : 90
property maxZoomSteps : 8 -- stop even if the picture never overflows
property settleSeconds : 2 -- full-screen animation; a zoom click during it is lost or misfires
property stepSeconds : 1 -- between View menu clicks, so each resize settles
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
			set value of attribute "AXFullScreen" of sessionWindow to true
			delay settleSeconds
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
	my viewMenuClick(proc, "Actual Size")
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

-- Each click resizes the picture. A click before that settles stacks on it.
on viewMenuClick(proc, itemName)
	tell application "System Events" to tell menu "View" of menu bar 1 of proc
		if exists menu item itemName then click menu item itemName
	end tell
	delay stepSeconds
end viewMenuClick

-- The shared screen gets scroll bars only while the picture is larger than the window.
on overflows(sessionWindow)
	tell application "System Events"
		return exists scroll bar 1 of (first UI element of sessionWindow whose role is "AXSharedScreen")
	end tell
end overflows

-- Without Accessibility permission, System Events refuses. Show the list and this app.
on askForPermission(errText)
	set appName to name of me
	do shell script "open -R " & quoted form of POSIX path of (path to me)
	open location permissionPane
	-- open location returns before System Settings comes forward; it would cover the dialog.
	repeat 20 times
		try
			tell application "System Events" to if frontmost of process "System Settings" then exit repeat
		end try
		delay 0.25
	end repeat
	delay 0.5
	activate
	display dialog appName & " needs Accessibility permission to set full screen. It did not connect." & return & return & ¬
		"1. If " & appName & " is already in the list, select it and click − to remove it. " & ¬
		"Each rebuild makes the old entry stale, even when it shows as on." & return & ¬
		"2. Drag " & appName & " from Finder into the list and turn it on." & return & ¬
		"3. Open " & appName & " again." & return & return & ¬
		"(" & errText & ")" buttons {"OK"} default button 1 with icon caution
end askForPermission
