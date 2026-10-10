-- Opens a saved Screen Sharing connection in full screen, with scaling set.
-- Template: build_app.py replaces the placeholders with AppleScript literals.
property connectionURL : __URL__
property windowTitle : __TITLE__
property scaleOn : __SCALE__
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
			my setScaling(it)
			set value of attribute "AXFullScreen" of sessionWindow to true
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

-- The View menu shows "Turn Scaling On" while scaling is off, and "Turn Scaling Off" while on.
on setScaling(proc)
	tell application "System Events"
		if scaleOn then
			set itemName to "Turn Scaling On"
		else
			set itemName to "Turn Scaling Off"
		end if
		tell menu "View" of menu bar 1 of proc
			if exists menu item itemName then click menu item itemName
		end tell
	end tell
end setScaling

-- Without Accessibility permission, System Events refuses. Show the list and this app.
on askForPermission(errText)
	set appName to name of me
	do shell script "open -R " & quoted form of POSIX path of (path to me)
	open location permissionPane
	display dialog appName & " needs Accessibility permission to set full screen." & return & return & ¬
		"Drag " & appName & " from Finder into the list, turn it on, then open it again." & return & return & ¬
		"(" & errText & ")" buttons {"OK"} default button 1 with icon caution
end askForPermission
