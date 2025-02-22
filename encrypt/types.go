package encrypt

/*
Used openssl to generate a random key:

openssl rand -base64 32
*/
var masterKeyStr = []byte("DSeM2Vg6jR6xtnPqwzYj8412DNZmeMfDPpNHNvZ0ucc=")
var masterKey = masterKeyStr[:32] // use the 1st 32 bytes of the master key
