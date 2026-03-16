import subprocess
script = """
tell application "System Events"
    set frontApp to name of first application process whose frontmost is true
end tell
if frontApp is "Google Chrome" or frontApp is "Brave Browser" or frontApp is "Microsoft Edge" then
    tell application frontApp to return URL of active tab of front window
else if frontApp is "Safari" then
    tell application "Safari" to return URL of front document
end if
return ""
"""
res = subprocess.run(["osascript", "-e", script], capture_output=True, text=True)
print("URL:", res.stdout.strip())
