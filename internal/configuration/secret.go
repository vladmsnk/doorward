package configuration

// SecretPurpose is the sealing purpose of a secret: bound to its name, so
// one secret's ciphertext cannot be moved under another name.
func SecretPurpose(name string) string { return "secret:" + name }
