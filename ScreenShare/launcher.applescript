-- Opens a macOS Screen Sharing session in full screen, with scaling set.
-- Template: Scripts/build_app.sh replaces __HOST__ and __SCALE__ and compiles it.
use framework "Foundation"
use scripting additions

property targetHost : "__HOST__"
property scaleOn : __SCALE__
property waitSeconds : 90

on run
	open location "vnc://" & targetHost
	set sessionWindow to my waitForSessionWindow()
	if sessionWindow is missing value then return
	tell application "System Events" to tell process "Screen Sharing"
		set frontmost to true
		perform action "AXRaise" of sessionWindow
		my setScaling(it)
		set value of attribute "AXFullScreen" of sessionWindow to true
	end tell
end run

-- The window title is the remote Mac's display name, not its hostname, so match on the
-- host in the connection file (AXDocument) that holds the vnc:// URL instead.
on waitForSessionWindow()
	repeat (waitSeconds * 2) times
		tell application "System Events"
			if exists process "Screen Sharing" then
				repeat with w in (windows of process "Screen Sharing")
					if my windowIsForHost(w) then return contents of w
				end repeat
			end if
		end tell
		delay 0.5
	end repeat
	return missing value
end waitForSessionWindow

on windowIsForHost(w)
	tell application "System Events"
		try
			set docURL to value of attribute "AXDocument" of w
		on error
			return false
		end try
	end tell
	if docURL is missing value then return false
	set connection to current application's NSDictionary's dictionaryWithContentsOfURL:(current application's NSURL's URLWithString:docURL)
	if connection is missing value then return false
	set sessionURL to connection's objectForKey:"URL"
	if sessionURL is missing value then return false
	set sessionHost to (current application's NSURL's URLWithString:sessionURL)'s |host|()
	if sessionHost is missing value then return false
	-- AppleScript text comparison ignores case, as hostnames do.
	return (sessionHost as text) = targetHost
end windowIsForHost

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
