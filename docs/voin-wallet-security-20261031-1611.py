#!/usr/bin/env python3
"""Install/test experimental encrypted wallet storage. No live key migration or deletion.
Use the resulting CLI interactively to protect/check/backup/restore TEST key files.
Unencrypted originals remain until a separately reviewed signing migration.
"""
import json
from pathlib import Path
import subprocess
import sys

STORE = r'''// Package walletcrypto provides experimental authenticated encryption for TEST wallets.
package walletcrypto

import (
    "bytes"
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "encoding/json"
    "errors"
    "io"
    "golang.org/x/crypto/scrypt"
)
const MaxPlaintext = 20000
const MaxEnvelope = 40000
const kdfName = "scrypt-N131072-r8-p1"
const cipherName = "AES-256-GCM"
var aad = []byte("VOIN/test-wallet-storage/v1|"+kdfName+"|"+cipherName)
type envelope struct {
    Version int `json:"version"`
    KDF string `json:"kdf"`
    Cipher string `json:"cipher"`
    Salt []byte `json:"salt"`
    Nonce []byte `json:"nonce"`
    Ciphertext []byte `json:"ciphertext"`
}
func Wipe(value []byte) { for i := range value { value[i] = 0 } }
func aead(password,salt []byte) (cipher.AEAD,error) {
    if len(password)<12 || len(password)>1024 { return nil,errors.New("password must be 12-1024 bytes") }
    key,err:=scrypt.Key(password,salt,131072,8,1,32)
    if err!=nil { return nil,err }
    defer Wipe(key)
    block,err:=aes.NewCipher(key)
    if err!=nil { return nil,err }
    return cipher.NewGCM(block)
}
func Seal(plain,password []byte) ([]byte,error) {
    if len(plain)==0 || len(plain)>MaxPlaintext { return nil,errors.New("invalid plaintext size") }
    salt:=make([]byte,32)
    if _,err:=io.ReadFull(rand.Reader,salt);err!=nil { return nil,err }
    box,err:=aead(password,salt)
    if err!=nil { return nil,err }
    nonce:=make([]byte,box.NonceSize())
    if _,err:=io.ReadFull(rand.Reader,nonce);err!=nil { return nil,err }
    return json.Marshal(envelope{1,kdfName,cipherName,salt,nonce,box.Seal(nil,nonce,plain,aad)})
}
func Open(raw,password []byte) ([]byte,error) {
    if len(raw)==0 || len(raw)>MaxEnvelope { return nil,errors.New("invalid envelope size") }
    var value envelope
    decoder:=json.NewDecoder(bytes.NewReader(raw));decoder.DisallowUnknownFields()
    if err:=decoder.Decode(&value);err!=nil { return nil,errors.New("invalid envelope") }
    canonical,err:=json.Marshal(value)
    if err!=nil || !bytes.Equal(raw,canonical) { return nil,errors.New("noncanonical envelope") }
    if value.Version!=1 || value.KDF!=kdfName || value.Cipher!=cipherName ||
        len(value.Salt)!=32 || len(value.Nonce)!=12 || len(value.Ciphertext)<17 ||
        len(value.Ciphertext)>MaxPlaintext+16 { return nil,errors.New("unsupported or invalid envelope") }
    box,err:=aead(password,value.Salt)
    if err!=nil { return nil,err }
    plain,err:=box.Open(nil,value.Nonce,value.Ciphertext,aad)
    if err!=nil { return nil,errors.New("wrong password or damaged encrypted wallet") }
    return plain,nil
}
'''
TEST = r'''package walletcrypto

import (
    "bytes"
    "encoding/json"
    "testing"
)
func TestEncryptedWalletRoundTripAndBackup(t *testing.T) {
    password:=[]byte("test-only-random-looking-passphrase")
    plain:=[]byte("TEST PRIVATE PAYLOAD - NOT A REAL KEY")
    first,err:=Seal(plain,password);if err!=nil { t.Fatal(err) }
    second,err:=Seal(plain,password);if err!=nil { t.Fatal(err) }
    if bytes.Equal(first,second) || bytes.Contains(first,plain) { t.Fatal("randomization or secrecy failed") }
    restored,err:=Open(append([]byte(nil),first...),password)
    if err!=nil || !bytes.Equal(restored,plain) { t.Fatal("backup round trip failed") }
    if _,err:=Open(first,[]byte("different-test-only-passphrase"));err==nil { t.Fatal("wrong password accepted") }
    var value envelope
    if err:=json.Unmarshal(first,&value);err!=nil { t.Fatal(err) }
    value.Ciphertext[0]^=1
    changed,_:=json.Marshal(value)
    if _,err:=Open(changed,password);err==nil { t.Fatal("tampering accepted") }
    value.KDF="scrypt-unbounded-parameters"
    changed,_=json.Marshal(value)
    if _,err:=Open(changed,password);err==nil { t.Fatal("unsupported KDF accepted") }
    if _,err:=Open(append(first,byte(' ')),password);err==nil { t.Fatal("extra data accepted") }
    if _,err:=Seal(plain,[]byte("short"));err==nil { t.Fatal("short password accepted") }
    if _,err:=Open(make([]byte,MaxEnvelope+1),password);err==nil { t.Fatal("oversized input accepted") }
}
'''
CLI = r'''// Experimental Linux TEST-wallet storage tool. Not a spending wallet or 2FA.
package main

import (
    "bytes"
    "crypto/sha256"
    "encoding/hex"
    "encoding/json"
    "errors"
    "flag"
    "fmt"
    "io"
    "os"
    "path/filepath"
    "regexp"
    "syscall"
    store "example.com/voin/abci/walletcrypto"
    "github.com/cloudflare/circl/sign/mldsa/mldsa44"
    "golang.org/x/term"
)
var validName=regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,100}$`)
func main() { if err:=run();err!=nil { fmt.Fprintln(os.Stderr,err);os.Exit(1) } }
func directory(name string) (string,error) {
    home,err:=os.UserHomeDir();if err!=nil { return "",err }
    path:=filepath.Join(home,name)
    if err:=os.Mkdir(path,0700);err!=nil && !os.IsExist(err) { return "",err }
    info,err:=os.Lstat(path);if err!=nil { return "",err }
    if !info.IsDir() || info.Mode().Perm()&0077!=0 { return "",errors.New("directory must be private and not a symlink") }
    return path,nil
}
func pathFor(dir,name string) (string,error) {
    if !validName.MatchString(name) { return "",errors.New("invalid filename") }
    return filepath.Join(dir,name),nil
}
func readPrivate(path string,limit int64) ([]byte,error) {
    fd,err:=syscall.Open(path,syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK,0)
    if err!=nil { return nil,err }
    file:=os.NewFile(uintptr(fd),path);defer file.Close()
    info,err:=file.Stat();if err!=nil { return nil,err }
    if !info.Mode().IsRegular() || info.Mode().Perm()!=0600 || info.Size()>limit {
        return nil,errors.New("expected a bounded regular0600 file")
    }
    data,err:=io.ReadAll(io.LimitReader(file,limit+1))
    if err!=nil || int64(len(data))>limit { return nil,errors.New("file read failed or exceeded limit") }
    return data,nil
}
func writeNew(path string,data []byte) error {
    file,err:=os.OpenFile(path,os.O_CREATE|os.O_EXCL|os.O_WRONLY,0600)
    if err!=nil { return err }
    if _,err:=file.Write(data);err!=nil { file.Close();return err }
    if err:=file.Sync();err!=nil { file.Close();return err }
    if err:=file.Close();err!=nil { return err }
    dir,err:=os.Open(filepath.Dir(path));if err!=nil { return err }
    defer dir.Close();return dir.Sync()
}
func password(confirm bool) ([]byte,error) {
    if !term.IsTerminal(int(os.Stdin.Fd())) { return nil,errors.New("interactive terminal required; no piped passwords") }
    fmt.Fprint(os.Stderr,"Test wallet passphrase (12+ bytes, input hidden): ")
    first,err:=term.ReadPassword(int(os.Stdin.Fd()));fmt.Fprintln(os.Stderr)
    if err!=nil { return nil,err }
    if len(first)<12 || len(first)>1024 { store.Wipe(first);return nil,errors.New("passphrase must be12-1024bytes") }
    if confirm {
        fmt.Fprint(os.Stderr,"Repeat passphrase (hidden): ")
        second,err:=term.ReadPassword(int(os.Stdin.Fd()));fmt.Fprintln(os.Stderr)
        equal:=bytes.Equal(first,second);store.Wipe(second)
        if err!=nil || !equal { store.Wipe(first);return nil,errors.New("passphrases differ") }
    }
    return first,nil
}
func validateKey(plain []byte) (string,error) {
    var value struct {
        Version int `json:"version"`
        Address string `json:"address"`
        PublicKey string `json:"public_key"`
        PrivateKey string `json:"private_key"`
    }
    if err:=json.Unmarshal(plain,&value);err!=nil { return "",errors.New("invalid test wallet") }
    public,err:=hex.DecodeString(value.PublicKey)
    if err!=nil || len(public)!=mldsa44.PublicKeySize || value.Version!=1 { return "",errors.New("invalid public key") }
    digest:=sha256.Sum256(public)
    if value.Address!="voin_"+hex.EncodeToString(digest[:]) { return "",errors.New("address mismatch") }
    secret,err:=hex.DecodeString(value.PrivateKey)
    if err!=nil || len(secret)!=mldsa44.PrivateKeySize { return "",errors.New("invalid private key") }
    defer store.Wipe(secret)
    var sk mldsa44.PrivateKey
    var pk mldsa44.PublicKey
    if err:=sk.UnmarshalBinary(secret);err!=nil { return "",errors.New("invalid private key") }
    if err:=pk.UnmarshalBinary(public);err!=nil { return "",errors.New("invalid public key") }
    signature:=make([]byte,mldsa44.SignatureSize)
    message:=[]byte("VOIN encrypted test wallet key-pair check")
    context:=[]byte("VOIN/wallet-storage-check/v1")
    if err:=mldsa44.SignTo(&sk,message,context,false,signature);err!=nil { return "",errors.New("key check failed") }
    if !mldsa44.Verify(&pk,message,context,signature) { return "",errors.New("public/private key mismatch") }
    return value.Address,nil
}
func run() error {
    action:=flag.String("action","","protect, check, backup, restore")
    source:=flag.String("source","","existing plaintext TEST-wallet basename")
    name:=flag.String("name","","encrypted wallet basename")
    backup:=flag.String("backup","","local encrypted-backup basename")
    flag.Parse()
    if *action!="protect" && *action!="check" && *action!="backup" && *action!="restore" { return errors.New("choose protect,check,backup,restore") }
    dir,err:=directory("voin-encrypted-test-wallets");if err!=nil { return err }
    path,err:=pathFor(dir,*name);if err!=nil { return err }
    var raw []byte
    if *action=="protect" {
        old,err:=directory("voin-test-wallets");if err!=nil { return err }
        oldPath,err:=pathFor(old,*source);if err!=nil { return err }
        raw,err=readPrivate(oldPath,store.MaxPlaintext);if err!=nil { return err }
        defer store.Wipe(raw)
        address,err:=validateKey(raw);if err!=nil { return err }
        pass,err:=password(true);if err!=nil { return err };defer store.Wipe(pass)
        encrypted,err:=store.Seal(raw,pass);if err!=nil { return err }
        verified,err:=store.Open(encrypted,pass);if err!=nil { return err }
        equal:=bytes.Equal(verified,raw);store.Wipe(verified)
        if !equal { return errors.New("encryption self-check failed") }
        if err:=writeNew(path,encrypted);err!=nil { return err }
        return json.NewEncoder(os.Stdout).Encode(map[string]string{"address":address,"encrypted_wallet":*name,
            "warning":"Original plaintext retained; old spending CLI still uses plaintext. Not production."})
    }
    backups,err:=directory("voin-encrypted-test-backups");if err!=nil { return err }
    backupPath:=""
    if *action=="backup" || *action=="restore" {
        backupPath,err=pathFor(backups,*backup);if err!=nil { return err }
    }
    input:=path;if *action=="restore" { input=backupPath }
    raw,err=readPrivate(input,store.MaxEnvelope);if err!=nil { return err }
    pass,err:=password(false);if err!=nil { return err };defer store.Wipe(pass)
    plain,err:=store.Open(raw,pass);if err!=nil { return err };defer store.Wipe(plain)
    address,err:=validateKey(plain);if err!=nil { return err }
    if *action=="backup" { if err:=writeNew(backupPath,raw);err!=nil { return err } }
    if *action=="restore" { if err:=writeNew(path,raw);err!=nil { return err } }
    return json.NewEncoder(os.Stdout).Encode(map[string]string{"address":address,"action":*action,
        "warning":"Local encrypted copy only; no remote backup, 2FA, multisig or spending integration"})
}
'''

def command(args,cwd,timeout=300):
    result=subprocess.run(args,cwd=cwd,capture_output=True,text=True,timeout=timeout)
    if result.returncode:
        raise RuntimeError('Command failed: '+' '.join(map(str,args))+'\n'+(result.stdout+result.stderr)[-5000:])
    return result.stdout


def main():
    repo=Path(subprocess.check_output(['git','rev-parse','--show-toplevel'],text=True).strip())
    if command(['git','branch','--show-current'],repo).strip()!='feature/signed-transfers':
        raise RuntimeError('Expected feature/signed-transfers')
    module=repo/'consensus/voin-app'
    files={'walletcrypto/storage.go':STORE,'walletcrypto/storage_test.go':TEST,
           'cmd/voin-wallet-storage/main.go':CLI}
    formatted={}
    for name,content in files.items():
        value=subprocess.run(['gofmt'],input=content,text=True,capture_output=True,timeout=30,check=True).stdout
        target=module/name
        if target.exists() and target.read_text()!=value:
            raise RuntimeError('Existing source differs; not overwritten: '+name)
        formatted[name]=value
    for name,value in formatted.items():
        target=module/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_text(value)
    print('RUN: resolve and record dependencies in go.mod/go.sum',flush=True)
    command(['go','mod','tidy'],module)
    print('RUN: encryption round trip, wrong password, tamper and malformed-input tests',flush=True)
    command(['go','test','-race','./...','-count=1','-timeout=180s'],module,timeout=360)
    command(['go','vet','./...'],module)
    command(['python','-m','unittest','discover','-s','tests'],repo)
    binary=Path.home()/'voin-tools/bin/voin-wallet-storage'
    command(['go','build','-o',str(binary),'./cmd/voin-wallet-storage'],module)
    print('ENCRYPTED STORAGE SOURCE CHECK PASS',flush=True)
    print('CLI:',binary,flush=True)
    print('No existing wallet encrypted, deleted, migrated or backed up automatically.',flush=True)
    print('No devnet process changed. No passwords read during automated tests.',flush=True)
    print('Interactive protect/check/backup/restore CLI installed for TEST keys only.',flush=True)
    print('Backup is a separate LOCAL encrypted copy; it is not off-device backup.',flush=True)
    print('Encrypted signing integration, independent factors and security audit remain undone.',flush=True)
    print('No git commit/push performed. Never send passwords or keys in chat.',flush=True)


if __name__=='__main__':
    try: main()
    except KeyboardInterrupt:
        print('Interrupted. Source files may remain; devnet and old keys unchanged.')
        raise SystemExit(130)
    except Exception as error:
        print('ENCRYPTED STORAGE PACKAGE NOT PASSED:',error,flush=True)
        raise SystemExit(1)
