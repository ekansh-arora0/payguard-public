import re
text = """
Check out this site: google.com/search?q=test
Or this one: https://apple.com.verify.xyz
Don't forget support@microsoft.com
Address bar: secure-login.chase.com
"""
urls1 = re.findall(r'https?://[^\s\'"<>)}\]]+', text)
print("Old regex:", urls1)

# Better regex that catches domains without http://
urls2 = re.findall(r'\b(?:https?://)?(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?:/[^\s\'"<>)}\]]*)?\b', text)
print("New regex:", urls2)
