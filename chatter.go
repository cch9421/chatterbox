// Implementation of a forward-secure, end-to-end encrypted messaging client
// supporting key compromise recovery and out-of-order message delivery.
// Directly inspired by Signal/Double-ratchet protocol but missing a few
// features. No asynchronous handshake support (pre-keys) for example.
//
// SECURITY WARNING: This code is meant for educational purposes and may
// contain vulnerabilities or other bugs. Please do not use it for
// security-critical applications.
//
// GRADING NOTES: This is the only file you need to modify for this assignment.
// You may add additional support files if desired. You should modify this file
// to implement the intended protocol, but preserve the function signatures
// for the following methods to ensure your implementation will work with
// standard test code:
//
// *NewChatter
// *EndSession
// *InitiateHandshake
// *ReturnHandshake
// *FinalizeHandshake
// *SendMessage
// *ReceiveMessage
//
// In addition, you'll need to keep all of the following structs' fields:
//
// *Chatter
// *Session
// *Message
//
// You may add fields if needed (not necessary) but don't rename or delete
// any existing fields.
//
// Original version
// Joseph Bonneau February 2019

package chatterbox

import "fmt"

import (
	//	"bytes" //un-comment for helpers like bytes.equal
	"encoding/binary"
	"errors"
	//	"fmt" //un-comment if you want to do any debug printing.
)

// Labels for key derivation

// Label for generating a check key from the initial root.
// Used for verifying the results of a handshake out-of-band.
const HANDSHAKE_CHECK_LABEL byte = 0x11

// Label for ratcheting the root key after deriving a key chain from it
const ROOT_LABEL = 0x22

// Label for ratcheting the main chain of keys
const CHAIN_LABEL = 0x33

// Label for deriving message keys from chain keys
const KEY_LABEL = 0x44

// Chatter represents a chat participant. Each Chatter has a single long-term
// key Identity, and a map of open sessions with other users (indexed by their
// identity keys). You should not need to modify this.
type Chatter struct {
	Identity *KeyPair
	Sessions map[PublicKey]*Session
}

// Session represents an open session between one chatter and another.
// You should not need to modify this, though you can add additional fields
// if you want to.
type Session struct {
	MyDHRatchet       *KeyPair
	PartnerDHRatchet  *PublicKey
	RootChain         *SymmetricKey
	SendChain         *SymmetricKey
	ReceiveChain      *SymmetricKey
	CachedReceiveKeys map[int]*SymmetricKey
	SendCounter       int
	LastUpdate        int
	ReceiveCounter    int
}

// Message represents a message as sent over an untrusted network.
// The first 5 fields are send unencrypted (but should be authenticated).
// The ciphertext contains the (encrypted) communication payload.
// You should not need to modify this.
type Message struct {
	Sender        *PublicKey
	Receiver      *PublicKey
	NextDHRatchet *PublicKey
	Counter       int
	LastUpdate    int
	Ciphertext    []byte
	IV            []byte
}

// EncodeAdditionalData encodes all of the non-ciphertext fields of a message
// into a single byte array, suitable for use as additional authenticated data
// in an AEAD scheme. You should not need to modify this code.
func (m *Message) EncodeAdditionalData() []byte {
	buf := make([]byte, 8+3*FINGERPRINT_LENGTH)

	binary.LittleEndian.PutUint32(buf, uint32(m.Counter))
	binary.LittleEndian.PutUint32(buf[4:], uint32(m.LastUpdate))

	if m.Sender != nil {
		copy(buf[8:], m.Sender.Fingerprint())
	}
	if m.Receiver != nil {
		copy(buf[8+FINGERPRINT_LENGTH:], m.Receiver.Fingerprint())
	}
	if m.NextDHRatchet != nil {
		copy(buf[8+2*FINGERPRINT_LENGTH:], m.NextDHRatchet.Fingerprint())
	}

	return buf
}

// NewChatter creates and initializes a new Chatter object. A long-term
// identity key is created and the map of sessions is initialized.
// You should not need to modify this code.
func NewChatter() *Chatter {
	c := new(Chatter)
	c.Identity = GenerateKeyPair()
	c.Sessions = make(map[PublicKey]*Session)
	return c
}

// EndSession erases all data for a session with the designated partner.
// All outstanding key material should be zeroized and the session erased.
func (c *Chatter) EndSession(partnerIdentity *PublicKey) error {

	if _, exists := c.Sessions[*partnerIdentity]; !exists {
		return errors.New("Don't have that session open to tear down")
	}

	delete(c.Sessions, *partnerIdentity)

	// TODO: your code here to zeroize remaining state

	return nil
}

// InitiateHandshake prepares the first message sent in a handshake, containing
// an ephemeral DH share. The partner which calls this method is the initiator.
func (c *Chatter) InitiateHandshake(partnerIdentity *PublicKey) (*PublicKey, error) {

	if _, exists := c.Sessions[*partnerIdentity]; exists {
		return nil, errors.New("Already have session open")
	}

	c.Sessions[*partnerIdentity] = &Session{
		MyDHRatchet:       GenerateKeyPair(),
		PartnerDHRatchet:  partnerIdentity,
		CachedReceiveKeys: make(map[int]*SymmetricKey),
		SendCounter:       0,
		LastUpdate:        1,
		ReceiveCounter:    0,
	}

	// TODO: your code here
	return &c.Sessions[*partnerIdentity].MyDHRatchet.PublicKey, nil

	return nil, errors.New("Not implemented")
}

// ReturnHandshake prepares the second message sent in a handshake, containing
// an ephemeral DH share. The partner which calls this method is the responder.
func (c *Chatter) ReturnHandshake(partnerIdentity,
	partnerEphemeral *PublicKey) (*PublicKey, *SymmetricKey, error) {

	if _, exists := c.Sessions[*partnerIdentity]; exists {
		return nil, nil, errors.New("Already have session open")
	}

	c.Sessions[*partnerIdentity] = &Session{
		MyDHRatchet:       GenerateKeyPair(),
		PartnerDHRatchet:  partnerEphemeral,
		CachedReceiveKeys: make(map[int]*SymmetricKey),
		SendCounter:       0, //do these need to be updated?
		LastUpdate:        0,
		ReceiveCounter:    0,
		// TODO: your code here
	}

	// TODO: your code here
	p1 := DHCombine(partnerIdentity, &c.Sessions[*partnerIdentity].MyDHRatchet.PrivateKey)
	p2 := DHCombine(partnerEphemeral, &c.Identity.PrivateKey)
	p3 := DHCombine(partnerEphemeral, &c.Sessions[*partnerIdentity].MyDHRatchet.PrivateKey)
	kroot := CombineKeys(p1, p2, p3)
	//fmt.Println("b1", p1, partnerEphemeral)
	//fmt.Println("b2", p2)
	//fmt.Println("b3", p3)

	c.Sessions[*partnerIdentity].RootChain = kroot
	//c.Sessions[*partnerIdentity].SendChain = kroot.Duplicate()
	c.Sessions[*partnerIdentity].ReceiveChain = kroot.Duplicate()

	checkkey := kroot.DeriveKey(HANDSHAKE_CHECK_LABEL)
	return &c.Sessions[*partnerIdentity].MyDHRatchet.PublicKey, checkkey, nil

	return nil, nil, errors.New("Not implemented")
}

// FinalizeHandshake lets the initiator receive the responder's ephemeral key
// and finalize the handshake.The partner which calls this method is the initiator.
func (c *Chatter) FinalizeHandshake(partnerIdentity,
	partnerEphemeral *PublicKey) (*SymmetricKey, error) {

	if _, exists := c.Sessions[*partnerIdentity]; !exists {
		return nil, errors.New("Can't finalize session, not yet open")
	}

	// TODO: your code here
	p1 := DHCombine(partnerEphemeral, &c.Identity.PrivateKey)
	p2 := DHCombine(partnerIdentity, &c.Sessions[*partnerIdentity].MyDHRatchet.PrivateKey)
	p3 := DHCombine(partnerEphemeral, &c.Sessions[*partnerIdentity].MyDHRatchet.PrivateKey)
	kroot := CombineKeys(p1, p2, p3)
	//fmt.Println("a1", p1)
	//fmt.Println("a2", p2)
	//fmt.Println("a3", p3)

	c.Sessions[*partnerIdentity].PartnerDHRatchet = partnerEphemeral
	c.Sessions[*partnerIdentity].RootChain = kroot
	c.Sessions[*partnerIdentity].SendChain = kroot.Duplicate()
	c.Sessions[*partnerIdentity].ReceiveChain = kroot.Duplicate()

	checkkey := kroot.DeriveKey(HANDSHAKE_CHECK_LABEL)
	return checkkey, nil

	return nil, errors.New("Not implemented")
}

// SendMessage is used to send the given plaintext string as a message.
// You'll need to implement the code to ratchet, derive keys and encrypt this message.
func (c *Chatter) SendMessage(partnerIdentity *PublicKey,
	plaintext string) (*Message, error) {
	//fmt.Println(plaintext)
	if _, exists := c.Sessions[*partnerIdentity]; !exists {
		return nil, errors.New("Can't send message to partner with no open session")
	}

	sess := c.Sessions[*partnerIdentity]
	//fmt.Println()
	if sess.SendChain == nil {
		//fmt.Print("inside", sess.RootChain)
		//temps
		tMyDHRatchet := GenerateKeyPair()
		tRootChain := CombineKeys(sess.RootChain.DeriveKey(ROOT_LABEL), DHCombine(sess.PartnerDHRatchet, &tMyDHRatchet.PrivateKey))

		sess.MyDHRatchet.Zeroize()
		sess.RootChain.Zeroize()
		//fmt.Println("after zero, trc", tRootChain, "rc", sess.RootChain)

		sess.MyDHRatchet = tMyDHRatchet
		sess.RootChain = tRootChain
		sess.SendChain = sess.RootChain.Duplicate()
		sess.LastUpdate = sess.SendCounter + 1
		//fmt.Println("after assignment, trc", tRootChain, "rc", sess.RootChain)
	}
	tSendChain := sess.SendChain.DeriveKey(CHAIN_LABEL)
	sess.SendChain.Zeroize()
	sess.SendChain = tSendChain
	//fmt.Println("sendcounter", sess.SendCounter, plaintext)
	sess.SendCounter = sess.SendCounter + 1

	iv := NewIV()

	message := &Message{
		Sender:   &c.Identity.PublicKey,
		Receiver: partnerIdentity,
		// TODO: your code here
		NextDHRatchet: &sess.MyDHRatchet.PublicKey,
		Counter:       sess.SendCounter,
		LastUpdate:    sess.LastUpdate,
		IV:            iv,
	}
	//fmt.Println("mcreated")
	// TODO: your code here
	message.Ciphertext = sess.SendChain.DeriveKey(KEY_LABEL).AuthenticatedEncrypt(plaintext, message.EncodeAdditionalData(), iv)

	//kroot
	//first hash chain value is derived from root key
	//update ur
	//if ur bob and alice sent a pubkey with different. update alice's ephemeral, update own keypair, update own
	//fmt.Println("sc", sess.SendChain, "done")
	//fmt.Println("rootc", sess.RootChain, "RC")
	//fmt.Println("senderkey", sess.MyDHRatchet.PublicKey)
	//fmt.Println(message)
	return message, nil
	return message, errors.New("Not implemented")
}

// ReceiveMessage is used to receive the given message and return the correct
// plaintext. This method is where most of the key derivation, ratcheting
// and out-of-order message handling logic happens.
func (c *Chatter) ReceiveMessage(message *Message) (string, error) {

	if _, exists := c.Sessions[*message.Sender]; !exists {
		return "", errors.New("Can't receive message from partner with no open session")
	}

	// TODO: your code here
	sess := c.Sessions[*message.Sender]

	//update DH ratchet keys
	//fmt.Println()
	//fmt.Println("abto root", sess.RootChain, "rec", sess.ReceiveChain)

	//temps
	tPartnerDHRatchet := sess.PartnerDHRatchet.Duplicate()
	tRootChain := sess.RootChain.Duplicate()
	tReceiveChain := sess.ReceiveChain.Duplicate()
	tReceiveCounter := sess.ReceiveCounter
	clearsc:=false
	//fmt.Println("temprcount", tReceiveCounter)

	if sess.ReceiveCounter+1 < message.LastUpdate {
		fmt.Print("preroot", message.Counter, sess.ReceiveCounter)
		for i := sess.ReceiveCounter + 1; i < message.LastUpdate; i++ {
			//fmt.Println("RC", i, sess.ReceiveChain)
			newrecchain := sess.ReceiveChain.DeriveKey(CHAIN_LABEL)
			sess.ReceiveChain.Zeroize()
			sess.ReceiveChain = newrecchain
			sess.CachedReceiveKeys[i] = sess.ReceiveChain.Duplicate()
		}
		sess.ReceiveCounter = message.LastUpdate - 1
		//fmt.Print(sess.CachedReceiveKeys)
	}

	if message.NextDHRatchet != nil && (((*message.NextDHRatchet).X).Cmp((*sess.PartnerDHRatchet).X)!=0 || ((*message.NextDHRatchet).Y).Cmp((*sess.PartnerDHRatchet).Y)!=0) && sess.ReceiveCounter <= message.LastUpdate {
		//fmt.Print("changing", message.NextDHRatchet)
		sess.PartnerDHRatchet = message.NextDHRatchet

		newrootchain := CombineKeys(sess.RootChain.DeriveKey(ROOT_LABEL), DHCombine(sess.PartnerDHRatchet, &sess.MyDHRatchet.PrivateKey))
		sess.RootChain.Zeroize()
		sess.RootChain=newrootchain

		sess.ReceiveChain.Zeroize()
		sess.ReceiveChain = sess.RootChain.Duplicate()
		//fmt.Println("new rc", sess.RootChain)

		clearsc=true
	}

	//check for out-of-order messages
	if message.Counter >= sess.ReceiveCounter+1 {
		//fmt.Print("entered", message.Counter, sess.ReceiveCounter)
		for i := sess.ReceiveCounter + 1; i <= message.Counter; i++ {
			
			newrecchain := sess.ReceiveChain.DeriveKey(CHAIN_LABEL)
			sess.ReceiveChain.Zeroize()
			sess.ReceiveChain=newrecchain

			//fmt.Println("RC", i, sess.ReceiveChain)

			sess.CachedReceiveKeys[i] = sess.ReceiveChain.Duplicate()
		}
		sess.ReceiveCounter = message.Counter
		//fmt.Print(sess.CachedReceiveKeys)
	}

	//retrieve correct key for encryption
	//deckey := sess.CachedReceiveKeys[message.Counter]
	deckey := sess.CachedReceiveKeys[message.Counter]
	//fmt.Println(message)
	//fmt.Println("deckey", deckey)
	// temps
	// tPartnerDHRatchet:=sess.PartnerDHRatchet.Duplicate()
	// tRootChain:=sess.RootChain.Duplicate()
	// tSendChain:=sess.SendChain.Duplicate()
	// tReceiveChain:=sess.ReceiveChain.Duplicate()
	// tReceiveCounter :=sess.ReceiveCounter

	//decrypt message
	plaintext, err := deckey.DeriveKey(KEY_LABEL).AuthenticatedDecrypt(message.Ciphertext, message.EncodeAdditionalData(), message.IV)
	if err != nil {
		fmt.Print("errrrrerer")
		sess.RootChain.Zeroize()
		sess.ReceiveChain.Zeroize()

		sess.PartnerDHRatchet = tPartnerDHRatchet
		sess.RootChain = tRootChain
		sess.ReceiveChain = tReceiveChain
		sess.ReceiveCounter = tReceiveCounter
		for i := sess.ReceiveCounter + 1; i <= message.Counter; i++ {
			sess.CachedReceiveKeys[i].Zeroize()
		}
		//fmt.Println("rec", sess.ReceiveChain)
		//fmt.Println("root", sess.RootChain)
		//fmt.Println(sess.ReceiveCounter)
		return "", err
	}
	fmt.Println("gethere", plaintext)

	//delete key and counter
	sess.CachedReceiveKeys[message.Counter].Zeroize()
	//sess.CachedReceiveKeys[message.Counter]=nil
	if(clearsc){
		if sess.SendChain != nil {
			sess.SendChain.Zeroize()
			sess.SendChain = nil
		}
	}

	return plaintext, nil
	return "", errors.New("Not implemented")
}
