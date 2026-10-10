-- Opens a saved Screen Sharing connection in full screen, then fits it with scaling or zoom.
-- Template: build_app.py replaces the placeholders with AppleScript literals.
property connectionURL : __URL__
property windowTitle : __TITLE__
property zoomInSteps : __ZOOM__ -- missing value = scale to fit
property waitSeconds : 90
property permissionPane : "x-apple.systempreferences:com.apple.settings.PrivacySecurity.extension?Privacy_Accessibility"

on run
	-- The URL is the saved connection's own address and user, so Screen Sharing reuses it.
	open location connectionURL
	try
		set sessionWindow to my waitForSessionWindow()
		if sessionWindow is missing value then return
		tell application "System Events" to tell process "Screen Sharing"
			set frontmost to true
			perform action "AXRaise" of sessionWindow
			set value of attribute "AXFullScreen" of sessionWindow to true
			delay 1.5 -- let the full-screen animation finish before resizing the picture
			my fitPicture(it)
		end tell
	on error errText number errNum
		my askForPermission(errText)
	end try
end run

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

-- Scaling only shrinks, so a remote smaller than this screen needs zoom to fill it.
-- The View menu shows "Turn Scaling On" only while scaling is off.
on fitPicture(proc)
	tell application "System Events" to tell menu "View" of menu bar 1 of proc
		if zoomInSteps is missing value then
			if exists menu item "Turn Scaling On" then click menu item "Turn Scaling On"
		else
			click menu item "Actual Size"
			repeat zoomInSteps times
				click menu item "Zoom In"
			end repeat
		end if
	end tell
end fitPicture

-- Without Accessibility permission, System Events refuses. Show the list and this app.
on askForPermission(errText)
	set appName to name of me
	do shell script "open -R " & quoted form of POSIX path of (path to me)
	open location permissionPane
	display dialog appName & " needs Accessibility permission to set full screen." & return & return & ¬
		"Drag " & appName & " from Finder into the list, turn it on, then open it again." & return & return & ¬
		"(" & errText & ")" buttons {"OK"} default button 1 with icon caution
end askForPermission
