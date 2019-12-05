
extern crate eng_wasm;
extern crate eng_wasm_derive;
extern crate serde;
extern crate hex;
extern crate enigma_crypto;
extern crate rustc_hex;
use enigma_crypto::{KeyPair, hash::Keccak256};
use serde::{Deserialize, Serialize};
use eng_wasm::*;
use rustc_hex::ToHex;
use std::collections::HashMap;


/*
 Encrypted state keys 
*/
static USER_ID: &str = "ID_";

type Id = String;
type Pass = String;
type AccountInfo = (Id, Pass, H160);

#[derive(Serialize, Deserialize, Default, Debug, Eq, PartialEq)]
pub struct Accounts (HashMap<String, Account>);
#[derive(Serialize, Deserialize, Default, Debug, Eq, PartialEq)]
pub struct Addresses  (HashMap<String, Id>);
#[derive(Serialize, Deserialize, Default, Debug, Eq, PartialEq)]
pub struct Account {
    id: Id,
    pass: Pass,
    current_address: H160,
}

//A marker that shows whether authentication is passed
#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
pub enum Authorize {
    ACCEPT,
    DENY,
}

fn prepare_hash_multiple<B: AsRef<[u8]>>(messages: &[B]) -> Vec<u8> {
    // wasmi is using a 32 bit target as oppose to the actual machine that
    // is a 64 bit target. therefore using u64 and not usize
    let mut res = Vec::with_capacity(messages.len() * mem::size_of::<u64>());
    for msg in messages {
        let msg = msg.as_ref();
        let len = (msg.len() as u64).to_be_bytes();
        res.extend_from_slice(&len);
        res.extend_from_slice(&msg);
    }
    res
}

/// verify if the address that is sending the tokens is the one who actually sent the transfer.
/// fix the function in "enigma-core/example/ERC20" to accept same message
/// メッセージと署名からpubkeyを導出する
/// this function can't define until enigmaMPC publishes function of authentication
fn verify(signer: H160, addr: H160, motions: String, sig: Vec<u8>) -> bool {
    let msg = [&addr.to_vec()[..], &motions.as_bytes()];
    let to_verify = prepare_hash_multiple(&msg);
    let mut new_sig: [u8; 65] = [0u8; 65];
    new_sig.copy_from_slice(&sig[..65]);

    let accepted_pubkey = KeyPair::recover(&to_verify, new_sig).unwrap();
    *signer == *accepted_pubkey.keccak256()
}

// returns user id by "ID_USERID"
fn make_id_string(id: &Id) -> String {
    let mut key = String::from(USER_ID);
    key.push_str(&id.to_string());
  
    return key;
  }
  
  // add prefix "0x" to address string
  fn make_address_string(address: &H160) -> String {
    let addr_str: String = address.to_hex();
  
    return [String::from("0x"), addr_str].concat();
  }

impl Accounts{
    fn read_state(&self, id: &String) -> Option<Account> {
        match self.0.get(id) {
            Some(account) => {
                let new_account = Account {
                    id: account.id.to_string(),
                    pass: account.pass.to_string(),
                    current_address: account.current_address,
                    };
            Some(new_account)
            },
            None => None
        }  
    }

    fn write_state(&mut self, id: String, account: Account) -> () {
        self.0.insert(id.to_string(), account);
    }
}

impl Addresses{
    fn read_state(&self, address: &String) -> Option<Id> {
        match self.0.get(address) {
            Some(id) => Some(id.to_string()),
            None => None
        } 
    }

    fn write_state(&mut self, address: String, id: Id) -> (){
        self.0.insert(address, id);
    }
}


// Private functions accessible only by the secret contract

    //return new account if id and address is not used
    fn register(id: &Id, pass: &Pass, address: &H160, accounts: &mut Accounts, addresses: &mut Addresses) -> Option<Account> {
        if is_exist(&id, accounts) | is_exist_address(&address, accounts, addresses){
            return None;
        } else {
            let new_account = Account{
                id: id.to_string(),
                pass: pass.to_string(),
                current_address:  *address
            };
            return Some(new_account);
        }
    }

    //authorize by using id password(for login)
    fn authorize_by_pass( id: &Id, pass: &Pass, accounts: &mut Accounts) -> Authorize {
        if &get_by_id(id, accounts).unwrap_or_default().pass == pass {
            return Authorize::ACCEPT;
        }
        return Authorize::DENY;
    }

    //authorize by using id address(for metamask)
    //third argument of verify function can be chosen by user in future
    fn authorize_by_address( address: H160, sig: Vec<u8>) -> Authorize {
        if verify(address, address, "Authentication by you".to_string(), sig) {
            return Authorize::ACCEPT;
        }
        return Authorize::DENY;
    }

    fn reset_pass(id: &Id, pass: &Pass, new_pass: &Pass, accounts: &mut Accounts) -> Result<Account, &'static str> {
        match authorize_by_pass(id, pass, accounts) {
            Authorize::ACCEPT => {
                let mut account = get_by_id(id, accounts).unwrap();
                account.id = id.to_string();
                account.pass = new_pass.to_string();
                Ok(account)
            },
            Authorize::DENY => {Err("Id or Pass is incorrect.")}
        }
    }

    fn reset_address(id: &Id, pass: &Pass, new_address: &H160, accounts: &mut Accounts) -> Result<Account, &'static str> {
        match authorize_by_pass(id, pass, accounts) {
            Authorize::ACCEPT => {
                let mut account = get_by_id(id, accounts).unwrap();
                account.current_address = *new_address;
                Ok(account)
            },
            Authorize::DENY => {Err("Id or Pass is incorrect.")}
        }
    }

    fn reset_pass_by_addr(address: H160, new_id: Id, new_pass: Pass, sig: Vec<u8>, accounts: &mut Accounts, addresses: &mut Addresses) -> Result<Account, &'static str> {
        match authorize_by_address(address, sig) {
            Authorize::ACCEPT => {
                let mut account = get_by_address(&address, accounts, addresses).unwrap();
                account.id = new_id.to_string();
                account.pass = new_pass.to_string();
                Ok(account)
            },
            Authorize::DENY => {Err("Id or Pass is incorrect.")}
        }
    }

    fn get_by_id (id: &Id, accounts: &mut Accounts) -> Option<Account> {
        let id_string = &make_id_string(id);
        match accounts.read_state(id_string){
            Some(account) => Some(account),
            None => None,
        }
    }

    fn get_by_address (address: &H160, accounts: &mut Accounts, addresses: &mut Addresses) -> Option<Account> {
        let address_string = &make_address_string(address);
        match addresses.read_state(address_string){
            Some(id) => {
                match get_by_id(&id, accounts){
                    Some(account) => Some(account),
                    None => None,
                }
            },
            None => None,
        }
    }

    fn is_exist(id: &Id, accounts: &mut Accounts) -> bool {
        match get_by_id(id, accounts) {
            Some(account) => true,
            None => false,
        }
    }

    fn is_exist_address(address: &H160, accounts: &mut Accounts, addresses: &mut Addresses) -> bool {
        match get_by_address(address, accounts, addresses) {
            Some(account) => true,
            None => false,
        }
    }

    fn register_in_state(account: Account, accounts: &mut Accounts, addresses: &mut Addresses) -> (){
        let id = account.id.to_string();
        let id_string = make_id_string(&account.id);
        let address_string = make_address_string(&account.current_address);
        accounts.write_state(id_string, account);
        addresses.write_state(address_string, id);
    }
    

    fn show_data(id: &Id, pass: &Pass, accounts: &mut Accounts) -> Option<AccountInfo> {
        match authorize_by_pass(id, pass, accounts) {
            Authorize::ACCEPT => {
                let account = &get_by_id(id, accounts).unwrap();
                Some((account.id.to_string(), account.pass.to_string(), account.current_address))
            },
            Authorize::DENY => None
        }
    }


#[cfg(test)]
    mod tests {
        use super::*;
        
    #[test]
    fn test_resister(){
        let id = "Namahage".to_string();
        let pass = "Creo".to_string();
        let address = H160::from_slice("9592b4af3004625D1Bfb".to_string().as_bytes());
        let mut accounts: Accounts = Accounts(HashMap::new());
        let mut addresses: Addresses = Addresses(HashMap::new());

        let account = Account{
            id: id.to_string(),
            pass: pass.to_string(),
            current_address: address,
        };
        let new_account = register(&id, &pass, &address, &mut accounts,&mut addresses).unwrap();
        assert_eq!(&new_account, &account,"account is not equal.");
        let id_str = make_id_string(&id);
        register_in_state(new_account, &mut accounts,&mut addresses);

        assert_eq!(register(&id, &pass, &address, &mut accounts,&mut addresses), None);
        assert_eq!(register(&"Namaha".to_string(), &pass, &address, &mut accounts,&mut addresses), None);
    }

    #[test]
    fn test_authorize_by_pass() {
        
        let id = "Namahage".to_string();
        let pass = "Creo".to_string();
        let address = H160::from_slice("9592b4af3004625D1Bfb".to_string().as_bytes());
        let mut accounts: Accounts = Accounts(HashMap::new());
        let mut addresses: Addresses = Addresses(HashMap::new());
        let new_account = register(&id, &pass, &address, &mut accounts,&mut addresses).unwrap();
        register_in_state(new_account, &mut accounts,&mut addresses);
        
        assert_eq!(authorize_by_pass(&id, &pass, &mut accounts), Authorize::ACCEPT);
        assert_eq!(authorize_by_pass(&id, &"N".to_string(), &mut accounts), Authorize::DENY);

    }

    #[test]
    fn test_reset_pass() {
        let id = "Namahage".to_string();
        let pass = "Creo".to_string();
        let address = H160::from_slice("9592b4af3004625D1Bfb".to_string().as_bytes());
        let mut accounts: Accounts = Accounts(HashMap::new());
        let mut addresses: Addresses = Addresses(HashMap::new());
        let new_account = register(&id, &pass, &address, &mut accounts,&mut addresses).unwrap();
        register_in_state(new_account, &mut accounts,&mut addresses);

        let new_pass = "RESET".to_string();
        let new_account = Account{
            id: id.to_string(),
            pass: new_pass.to_string(),
            current_address: address,
        };
        assert_eq!(reset_pass(&id, &pass, &new_pass, &mut accounts).unwrap(), new_account);
        assert!(reset_pass(&id, &"N".to_string(), &new_pass, &mut accounts).is_err())

    }

    #[test]
    fn test_reset_address() {
        let id = "Namahage".to_string();
        let pass = "Creo".to_string();
        let address = H160::from_slice("9592b4af3004625D1Bfb".to_string().as_bytes());
        let mut accounts: Accounts = Accounts(HashMap::new());
        let mut addresses: Addresses = Addresses(HashMap::new());
        let new_account = register(&id, &pass, &address, &mut accounts,&mut addresses).unwrap();
        register_in_state(new_account, &mut accounts,&mut addresses);

        let new_address = H160::from_slice("9592b4af3004625D1Bfa".to_string().as_bytes());
        let new_account = Account{
            id: id.to_string(),
            pass: pass.to_string(),
            current_address: new_address,
        };
        assert_eq!(reset_address(&id, &pass, &new_address, &mut accounts).unwrap(), new_account);
        assert!(reset_address(&id, &"N".to_string(), &new_address, &mut accounts).is_err())

    }

    #[test]
    fn test_show_data() {
        let id = "Namahage".to_string();
        let pass = "Creo".to_string();
        let address = H160::from_slice("9592b4af3004625D1Bfb".to_string().as_bytes());
        let mut accounts: Accounts = Accounts(HashMap::new());
        let mut addresses: Addresses = Addresses(HashMap::new());
        let new_account = register(&id, &pass, &address, &mut accounts,&mut addresses).unwrap();
        register_in_state(new_account, &mut accounts,&mut addresses);

        let data = show_data(&id, &pass, &mut accounts).unwrap();
        assert_eq!(data, (id.to_string(), pass.to_string(), address));
        assert_eq!(show_data(&id, &"N".to_string(), &mut accounts), None);
    }
}