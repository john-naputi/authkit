fuzz:
	go test ./internaltest -run=^$ -fuzz=FuzzStart_RedirectPath -fuzztime=10s
	go test ./internaltest -run=^$ -fuzz=FuzzTokenEndpoints    -fuzztime=10s
