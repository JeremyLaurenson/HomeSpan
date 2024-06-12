/*********************************************************************************
 *  MIT License
 *  
 *  Copyright (c) 2020-2024 Gregg E. Berman
 *  
 *  https://github.com/HomeSpan/HomeSpan
 *  
 *  Permission is hereby granted, free of charge, to any person obtaining a copy
 *  of this software and associated documentation files (the "Software"), to deal
 *  in the Software without restriction, including without limitation the rights
 *  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 *  copies of the Software, and to permit persons to whom the Software is
 *  furnished to do so, subject to the following conditions:
 *  
 *  The above copyright notice and this permission notice shall be included in all
 *  copies or substantial portions of the Software.
 *  
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 *  SOFTWARE.
 *  
 ********************************************************************************/
 
#include <ESPmDNS.h>
#include <core_version.h>
#ifdef ARDUINO_ESP32_RELEASE_3_0_0
# error HomeSpan currently does not work on the Espressif Board 3.0 definitions$
#endif
#include <sodium.h>
#include <MD5Builder.h>
#include <mbedtls/version.h>

#include "HAP.h"

//////////////////////////////////////

void HAPClient::init(){

  size_t len;                                   // not used but required to read blobs from NVS

  nvs_open("SRP",NVS_READWRITE,&srpNVS);        // open SRP data namespace in NVS 
  nvs_open("HAP",NVS_READWRITE,&hapNVS);        // open HAP data namespace in NVS

  if(strlen(homeSpan.spanOTA.otaPwd)==0){                                 // OTA password has not been specified in sketch
    if(!nvs_get_str(homeSpan.otaNVS,"OTADATA",NULL,&len)){                // if found OTA data in NVS...
    nvs_get_str(homeSpan.otaNVS,"OTADATA",homeSpan.spanOTA.otaPwd,&len);  // ...retrieve data.
    } else {                                                              // otherwise...
    homeSpan.spanOTA.setPassword(DEFAULT_OTA_PASSWORD);                   // ...use default password
    }
  }
  
  if(nvs_get_blob(srpNVS,"VERIFYDATA",NULL,&len))                         // if Pair-Setup verification code data not found in NVS
    homeSpan.setPairingCode(DEFAULT_SETUP_CODE);                          // create and save verification from using Pairing Setup Code

  if(!strlen(homeSpan.qrID)){                                             // is Setup ID has not been specified in sketch
    if(!nvs_get_str(hapNVS,"SETUPID",NULL,&len)){                         // check for saved value
      nvs_get_str(hapNVS,"SETUPID",homeSpan.qrID,&len);                   // retrieve data
    } else {
      sprintf(homeSpan.qrID,"%s",DEFAULT_QR_ID);                          // use default
   }
  }
  
  if(!nvs_get_blob(hapNVS,"ACCESSORY",NULL,&len)){                        // if found long-term Accessory data in NVS
    nvs_get_blob(hapNVS,"ACCESSORY",&accessory,&len);                     // retrieve data
  } else {      
    LOG0("Generating new random Accessory ID and Long-Term Ed25519 Signature Keys...\n\n");
    uint8_t buf[6];
    char cBuf[18];
    
    randombytes_buf(buf,6);                                              // generate 6 random bytes using libsodium (which uses the ESP32 hardware-based random number generator)
    sprintf(cBuf,"%02X:%02X:%02X:%02X:%02X:%02X",                        // create ID in form "XX:XX:XX:XX:XX:XX" (HAP Table 6-7)
      buf[0],buf[1],buf[2],buf[3],buf[4],buf[5]);

    memcpy(accessory.ID,cBuf,17);                                        // copy into Accessory ID for permanent storage
    crypto_sign_keypair(accessory.LTPK,accessory.LTSK);                  // generate new random set of keys using libsodium public-key signature
    
    nvs_set_blob(hapNVS,"ACCESSORY",&accessory,sizeof(accessory));       // update data
    nvs_commit(hapNVS);                                                  // commit to NVS
  }

  if(!nvs_get_blob(hapNVS,"CONTROLLERS",NULL,&len)){                     // if found long-term Controller Pairings data from NVS
    TempBuffer<Controller> tBuf(len/sizeof(Controller));
    nvs_get_blob(hapNVS,"CONTROLLERS",tBuf,&len);                        // retrieve data
    for(int i=0;i<tBuf.size();i++){
      if(tBuf[i].allocated)
        controllerList.push_back(tBuf[i]);
    }
  }
  
  LOG0("Accessory ID:      ");
  charPrintRow(accessory.ID,17);
  LOG0("                               LTPK: ");
  hexPrintRow(accessory.LTPK,32);
  LOG0("\n");

  printControllers();                                                         

  if(!nvs_get_blob(hapNVS,"HAPHASH",NULL,&len)){                 // if found HAP HASH structure
    nvs_get_blob(hapNVS,"HAPHASH",&homeSpan.hapConfig,&len);     // retrieve data    
  } else {
    LOG0("Resetting Database Hash...\n");
    nvs_set_blob(hapNVS,"HAPHASH",&homeSpan.hapConfig,sizeof(homeSpan.hapConfig));     // save data (will default to all zero values, which will then be updated below)
    nvs_commit(hapNVS);                                                                // commit to NVS
  }

  if(homeSpan.updateDatabase(false)){       // create Configuration Number and Loop vector
    LOG0("\nAccessory configuration has changed.  Updating configuration number to %d\n",homeSpan.hapConfig.configNumber);
  }
  else{
    LOG0("\nAccessory configuration number: %d\n",homeSpan.hapConfig.configNumber);
  }

  LOG0("\n");

}

//////////////////////////////////////

void HAPClient::processRequest(){

  int nBytes, messageSize;

  messageSize=client.available();        

  if(messageSize>MAX_HTTP){                         // exceeded maximum number of bytes allowed
    badRequestError();
    LOG0("\n*** ERROR:  HTTP message of %d bytes exceeds maximum allowed (%d)\n\n",messageSize,MAX_HTTP);
    return;
  }
 
  TempBuffer<uint8_t> httpBuf(messageSize+1);      // leave room for null character added below
  
  if(cPair){                                       // expecting encrypted message
    LOG2("<<<< #### ");
    LOG2(client.remoteIP());
    LOG2(" #### <<<<\n");

    nBytes=receiveEncrypted(httpBuf,messageSize);  // decrypt and return number of bytes read      
        
    if(!nBytes){                                   // decryption failed (error message already printed in function)
      badRequestError();              
      return;          
    }
        
  } else {                                         // expecting plaintext message  
    LOG2("<<<<<<<<< ");
    LOG2(client.remoteIP());
    LOG2(" <<<<<<<<<\n");
    
    nBytes=client.read(httpBuf,messageSize);       // read expected number of bytes

    if(nBytes!=messageSize || client.available()!=0){
      badRequestError();
      LOG0("\n*** ERROR:  HTTP message not read correctly.  Expected %d bytes, read %d bytes, %d bytes remaining\n\n",messageSize,nBytes,client.available());
      return;
    }
               
  } // encrypted/plaintext
      
  httpBuf[nBytes]='\0';   // add null character to enable string functions
      
  char *body=(char *)httpBuf.get();   // char pointer to start of HTTP Body
  char *p;                            // char pointer used for searches
     
  if(!(p=strstr((char *)httpBuf.get(),"\r\n\r\n"))){
    badRequestError();
    LOG0("\n*** ERROR:  Malformed HTTP request (can't find blank line indicating end of BODY)\n\n");
    return;      
  }

  *p='\0';                            // null-terminate end of HTTP Body to faciliate additional string processing
  uint8_t *content=(uint8_t *)p+4;    // byte pointer to start of optional HTTP Content
  int cLen=0;                         // length of optional HTTP Content

  if((p=strstr(body,"Content-Length: ")))       // Content-Length is specified
    cLen=atoi(p+16);
  if(nBytes!=strlen(body)+4+cLen){
    badRequestError();
    LOG0("\n*** ERROR:  Malformed HTTP request (Content-Length plus Body Length does not equal total number of bytes read)\n\n");
    return;        
  }

  LOG2(body);
  LOG2("\n------------ END BODY! ------------\n");

  if(!strncmp(body,"POST ",5)){                                                                                        // this is a POST request

    if(cLen==0){
      badRequestError();
      LOG0("\n*** ERROR:  HTTP POST request contains no Content\n\n");
    }
           
    else if(!strncmp(body,"POST /pair-setup ",17) && strstr(body,"Content-Type: application/pairing+tlv8"))            // POST PAIR-SETUP               
      postPairSetupURL(content,cLen);

    else if(!strncmp(body,"POST /pair-verify ",18) && strstr(body,"Content-Type: application/pairing+tlv8"))           // POST PAIR-VERIFY 
      postPairVerifyURL(content,cLen);
            
    else if(!strncmp(body,"POST /pairings ",15) && strstr(body,"Content-Type: application/pairing+tlv8"))              // POST PAIRINGS                
      postPairingsURL(content,cLen);

    else {
      notFoundError();
      LOG0("\n*** ERROR:  Bad POST request - URL not found\n\n");
    }
    
    return;                          
  } // POST request
          
  if(!strncmp(body,"PUT ",4)){                                                                                         // this is a PUT request

    if(cLen==0){
      badRequestError();
      LOG0("\n*** ERROR:  HTTP PUT request contains no Content\n\n");
      return;
    }

    LOG2((char *)content);
    LOG2("\n------------ END JSON! ------------\n");    
           
    if(!strncmp(body,"PUT /characteristics ",21) && strstr(body,"Content-Type: application/hap+json"))                 // PUT CHARACTERISTICS              
      putCharacteristicsURL((char *)content);

    else if(!strncmp(body,"PUT /prepare ",13) && strstr(body,"Content-Type: application/hap+json"))                    // PUT PREPARE
      putPrepareURL((char *)content);

    else {
      notFoundError();
      LOG0("\n*** ERROR:  Bad PUT request - URL not found\n\n");
    }
    
    return;                  
        
  } // PUT request           
      
  if(!strncmp(body,"GET ",4)){                                                                                         // this is a GET request
                    
    if(!strncmp(body,"GET /accessories ",17))                                                                          // GET ACCESSORIES
      getAccessoriesURL();

    else if(!strncmp(body,"GET /characteristics?",21))                                                                 // GET CHARACTERISTICS
      getCharacteristicsURL(body+21);

    else if(homeSpan.webLog.isEnabled && !strncmp(body,homeSpan.webLog.statusURL.c_str(),homeSpan.webLog.statusURL.length()))       // GET STATUS - AN OPTIONAL, NON-HAP-R2 FEATURE
      getStatusURL(this,NULL,NULL);

    else {
      notFoundError();
      LOG0("\n*** ERROR:  Bad GET request - URL not found\n\n");
    }
    
    return;                  

  } // GET request
      
  badRequestError();
  LOG0("\n*** ERROR:  Unknown or malformed HTTP request\n\n");
                        
} // processHAP

//////////////////////////////////////

int HAPClient::notFoundError(){

  char s[]="HTTP/1.1 404 Not Found\r\n\r\n";
  LOG2("\n>>>>>>>>>> ");
  LOG2(client.remoteIP());
  LOG2(" >>>>>>>>>>\n");
  LOG2(s);
  client.print(s);
  LOG2("------------ SENT! --------------\n");
  
  delay(1);
  client.stop();

  return(-1);
}

//////////////////////////////////////

int HAPClient::badRequestError(){

  char s[]="HTTP/1.1 400 Bad Request\r\n\r\n";
  LOG2("\n>>>>>>>>>> ");
  LOG2(client.remoteIP());
  LOG2(" >>>>>>>>>>\n");
  LOG2(s);
  client.print(s);
  LOG2("------------ SENT! --------------\n");
  
  delay(1);
  client.stop();

  return(-1);
}

//////////////////////////////////////

int HAPClient::unauthorizedError(){

  char s[]="HTTP/1.1 470 Connection Authorization Required\r\n\r\n";
  LOG2("\n>>>>>>>>>> ");
  LOG2(client.remoteIP());
  LOG2(" >>>>>>>>>>\n");
  LOG2(s);
  client.print(s);
  LOG2("------------ SENT! --------------\n");
  
  delay(1);
  client.stop();

  return(-1);
}

//////////////////////////////////////

int HAPClient::postPairSetupURL(uint8_t *content, size_t len){

  HAPTLV iosTLV;
  HAPTLV responseTLV;
  HAPTLV subTLV;

  iosTLV.unpack(content,len);
  if(homeSpan.getLogLevel()>1)
    iosTLV.print();
  LOG2("------------ END TLVS! ------------\n");

  LOG1("In Pair Setup #%d (%s)...",conNum,client.remoteIP().toString().c_str());
  
  auto itState=iosTLV.find(kTLVType_State);

  if(iosTLV.len(itState)!=1){                                   // missing STATE TLV
    LOG0("\n*** ERROR: Missing or invalid 'State' TLV\n\n");
    badRequestError();                                          // return with 400 error, which closes connection      
    return(0);
  }

  int tlvState=(*itState)[0];

  if(nAdminControllers()){                                  // error: Device already paired (i.e. there is at least one admin Controller). We should not be receiving any requests for Pair-Setup!
    LOG0("\n*** ERROR: Device already paired!\n\n");
    responseTLV.add(kTLVType_State,tlvState+1);             // set response STATE to requested state+1 (which should match the state that was expected by the controller)
    responseTLV.add(kTLVType_Error,tagError_Unavailable);   // set Error=Unavailable
    tlvRespond(responseTLV);                                // send response to client
    return(0);
  };

  LOG2("Found <M%d>.  Expected <M%d>.\n",tlvState,pairStatus);

  if(tlvState!=pairStatus){                                         // error: Device is not yet paired, but out-of-sequence pair-setup STATE was received
    LOG0("\n*** ERROR: Out-of-Sequence Pair-Setup request!\n\n");
    responseTLV.add(kTLVType_State,tlvState+1);                     // set response STATE to requested state+1 (which should match the state that was expected by the controller)
    responseTLV.add(kTLVType_Error,tagError_Unknown);               // set Error=Unknown (there is no specific error type for out-of-sequence steps)
    tlvRespond(responseTLV);                                        // send response to client
    pairStatus=pairState_M1;                                        // reset pairStatus to first step of unpaired accessory (M1)
    return(0);
  };
   
  switch(tlvState){                                         // valid and in-sequence Pair-Setup STATE received -- process request!  (HAP Section 5.6)

    case pairState_M1:{                                     // 'SRP Start Request'

      responseTLV.add(kTLVType_State,pairState_M2);                             // set State=<M2>

      auto itMethod=iosTLV.find(kTLVType_Method);

      if(iosTLV.len(itMethod)!=1 || (*itMethod)[0]!=0){                         // error: "Pair Setup" method must always be 0 to indicate setup without MiFi Authentification (HAP Table 5-3)
        LOG0("\n*** ERROR: Pair 'Method' missing or not set to 0\n\n");
        responseTLV.add(kTLVType_Error,tagError_Unavailable);                   // set Error=Unavailable
        tlvRespond(responseTLV);                                                // send response to client
        return(0);
      };

      auto itPublicKey=responseTLV.add(kTLVType_PublicKey,384,NULL);                // create blank PublicKey TLV with space for 384 bytes

      if(srp==NULL)                                                                 // create instance of SRP (if not already created) to persist until Pairing-Setup M5 completes
        srp=new SRP6A;
        
      TempBuffer<Verification> verifyData;                                          // retrieve verification data (should already be stored in NVS)
      size_t len=verifyData.len();
      nvs_get_blob(srpNVS,"VERIFYDATA",verifyData,&len);

      responseTLV.add(kTLVType_Salt,16,verifyData.get()->salt);                     // write Salt from verification data into TLV
      
      srp->createPublicKey(verifyData,*itPublicKey);                                // create accessory Public Key from stored verification data and write result into PublicKey TLV
      
      tlvRespond(responseTLV);                                                      // send response to client
      pairStatus=pairState_M3;                                                      // set next expected pair-state request from client
      return(1);
    } 
    break;

    case pairState_M3:{                                     // 'SRP Verify Request'

      responseTLV.add(kTLVType_State,pairState_M4);                     // set State=<M4>

      auto itPublicKey=iosTLV.find(kTLVType_PublicKey);
      auto itClientProof=iosTLV.find(kTLVType_Proof);

      if(iosTLV.len(itPublicKey)<=0 || iosTLV.len(itClientProof)!=64){
        LOG0("\n*** ERROR: One or both of the required 'PublicKey' and 'Proof' TLV records for this step is bad or missing\n\n");
        responseTLV.add(kTLVType_Error,tagError_Unknown);               // set Error=Unknown (there is no specific error type for missing/bad TLV data)
        tlvRespond(responseTLV);                                        // send response to client
        pairStatus=pairState_M1;                                        // reset pairStatus to first step of unpaired
        return(0);
      };

      srp->createSessionKey(*itPublicKey,(*itPublicKey).len);                 // create session key, K, from client Public Key, A

      if(!srp->verifyClientProof(*itClientProof)){                            // verify client Proof, M1
        LOG0("\n*** ERROR: SRP Proof Verification Failed\n\n");
        responseTLV.add(kTLVType_Error,tagError_Authentication);              // set Error=Authentication
        tlvRespond(responseTLV);                                              // send response to client
        pairStatus=pairState_M1;                                              // reset pairStatus to first step of unpaired
        return(0);        
      };

      auto itAccProof=responseTLV.add(kTLVType_Proof,64,NULL);                // create blank accessory Proof TLV with space for 64 bytes

      srp->createAccProof(*itAccProof);                                       // M1 has been successully verified; now create accessory Proof M2

      tlvRespond(responseTLV);                                                // send response to client
      pairStatus=pairState_M5;                                                // set next expected pair-state request from client
     
      return(1);        
    }
    break;
    
    case pairState_M5:{                                     // 'Exchange Request'

      responseTLV.add(kTLVType_State,pairState_M6);                     // set State=<M6>

      auto itEncryptedData=iosTLV.find(kTLVType_EncryptedData);

      if(iosTLV.len(itEncryptedData)<=0){            
        LOG0("\n*** ERROR: Required 'EncryptedData' TLV record for this step is bad or missing\n\n");
        responseTLV.add(kTLVType_Error,tagError_Unknown);               // set Error=Unknown (there is no specific error type for missing/bad TLV data)
        tlvRespond(responseTLV);                                        // send response to client
        pairStatus=pairState_M1;                                        // reset pairStatus to first step of unpaired
        return(0);
      };

      // THIS NEXT STEP IS MISSING FROM HAP DOCUMENTATION!
      //
      // Must FIRST use HKDF to create a Session Key from the SRP Shared Secret for use in subsequent ChaCha20-Poly1305 decryption
      // of the encrypted data TLV (HAP Sections 5.6.5.2 and 5.6.6.1).
      //
      // Note the SALT and INFO text fields used by HKDF to create this Session Key are NOT the same as those for creating iosDeviceX.
      // The iosDeviceX HKDF calculations are separate and will be performed further below with the SALT and INFO as specified in the HAP docs.

      TempBuffer<uint8_t> sessionKey(crypto_box_PUBLICKEYBYTES);                                            // temporary space - used only in this block     
      hkdf.create(sessionKey,srp->K,64,"Pair-Setup-Encrypt-Salt","Pair-Setup-Encrypt-Info");                // create SessionKey

      LOG2("------- DECRYPTING SUB-TLVS -------\n");
      
      // use SessionKey to decrypt encryptedData TLV with padded nonce="PS-Msg05"
                                  
      TempBuffer<uint8_t> decrypted((*itEncryptedData).len-crypto_aead_chacha20poly1305_IETF_ABYTES);       // temporary storage for decrypted data
       
      if(crypto_aead_chacha20poly1305_ietf_decrypt(decrypted, NULL, NULL, *itEncryptedData, (*itEncryptedData).len, NULL, 0, (unsigned char *)"\x00\x00\x00\x00PS-Msg05", sessionKey)==-1){          
        LOG0("\n*** ERROR: Exchange-Request Authentication Failed\n\n");
        responseTLV.add(kTLVType_Error,tagError_Authentication);        // set Error=Authentication
        tlvRespond(responseTLV);                                        // send response to client
        pairStatus=pairState_M1;                                        // reset pairStatus to first step of unpaired
        return(0);        
      }

      subTLV.unpack(decrypted,decrypted.len());                         // unpack TLV      
      if(homeSpan.getLogLevel()>1)
        subTLV.print();                                                 // print decrypted TLV data
      
      LOG2("---------- END SUB-TLVS! ----------\n");

      auto itIdentifier=subTLV.find(kTLVType_Identifier);
      auto itSignature=subTLV.find(kTLVType_Signature);
      auto itPublicKey=subTLV.find(kTLVType_PublicKey);

      if(subTLV.len(itIdentifier)!=hap_controller_IDBYTES || subTLV.len(itSignature)!=crypto_sign_BYTES || subTLV.len(itPublicKey)!=crypto_sign_PUBLICKEYBYTES){ 
        LOG0("\n*** ERROR: One or more of required 'Identifier,' 'PublicKey,' and 'Signature' TLV records for this step is bad or missing\n\n");
        responseTLV.add(kTLVType_Error,tagError_Unknown);               // set Error=Unknown (there is no specific error type for missing/bad TLV data)
        tlvRespond(responseTLV);                                        // send response to client
        pairStatus=pairState_M1;                                        // reset pairStatus to first step of unpaired
        return(0);
      };

      // Next, verify the authenticity of the TLV Records using the Signature provided by the Client.
      // But the Client does not send the entire message that was used to generate the Signature.
      // Rather, it purposely does not transmit "iosDeviceX", which is derived from the SRP Shared Secret that only the Client and this Server know.
      // Note that the SALT and INFO text fields now match those in HAP Section 5.6.6.1

      TempBuffer<uint8_t> iosDeviceX(32);
      hkdf.create(iosDeviceX,srp->K,64,"Pair-Setup-Controller-Sign-Salt","Pair-Setup-Controller-Sign-Info");     // derive iosDeviceX (32 bytes) from SRP Shared Secret using HKDF 

      // Concatenate iosDeviceX, IOS ID, and IOS PublicKey into iosDeviceInfo
      
      TempBuffer<uint8_t> iosDeviceInfo(iosDeviceX,iosDeviceX.len(),(*itIdentifier).val.get(),(*itIdentifier).len,(*itPublicKey).val.get(),(*itPublicKey).len,NULL);

      if(crypto_sign_verify_detached(*itSignature, iosDeviceInfo, iosDeviceInfo.len(), *itPublicKey) != 0){      // verify signature of iosDeviceInfo using iosDeviceLTPK   
        LOG0("\n*** ERROR: LPTK Signature Verification Failed\n\n");
        responseTLV.add(kTLVType_Error,tagError_Authentication);        // set Error=Authentication
        tlvRespond(responseTLV);                                        // send response to client
        pairStatus=pairState_M1;                                        // reset pairStatus to first step of unpaired
        return(0);                
      }

      addController(*itIdentifier,*itPublicKey,true);                   // save Pairing ID and LTPK for this Controller with admin privileges

      // Now perform the above steps in reverse to securely transmit the AccessoryLTPK to the Controller (HAP Section 5.6.6.2)

      TempBuffer<uint8_t> accessoryX(32);
      hkdf.create(accessoryX,srp->K,64,"Pair-Setup-Accessory-Sign-Salt","Pair-Setup-Accessory-Sign-Info");       // derive accessoryX from SRP Shared Secret using HKDF 
      
      // Concatenate accessoryX, Accessory ID, and Accessory PublicKey into accessoryInfo

      TempBuffer<uint8_t> accessoryInfo(accessoryX,accessoryX.len(),accessory.ID,hap_accessory_IDBYTES,accessory.LTPK,crypto_sign_PUBLICKEYBYTES,NULL);

      subTLV.clear();                                                                            // clear existing SUBTLV records

      itSignature=subTLV.add(kTLVType_Signature,64,NULL);                                        // create blank Signature TLV with space for 64 bytes

      crypto_sign_detached(*itSignature,NULL,accessoryInfo,accessoryInfo.len(),accessory.LTSK);  // produce signature of accessoryInfo using AccessoryLTSK (Ed25519 long-term secret key)

      subTLV.add(kTLVType_Identifier,hap_accessory_IDBYTES,accessory.ID);                        // set Identifier TLV record as accessoryPairingID
      subTLV.add(kTLVType_PublicKey,crypto_sign_PUBLICKEYBYTES,accessory.LTPK);                  // set PublicKey TLV record as accessoryLTPK

      LOG2("------- ENCRYPTING SUB-TLVS -------\n");

      if(homeSpan.getLogLevel()>1)
        subTLV.print();

      TempBuffer<uint8_t> subPack(subTLV.pack_size());                                           // create sub-TLV by packing Identifier, PublicKey and Signature TLV records together
      subTLV.pack(subPack);      

      // Encrypt the subTLV data using the same SRP Session Key as above with ChaCha20-Poly1305

      itEncryptedData=responseTLV.add(kTLVType_EncryptedData,subPack.len()+crypto_aead_chacha20poly1305_IETF_ABYTES,NULL);     //create blank EncryptedData TLV with space for subTLV + Authentication Tag

      crypto_aead_chacha20poly1305_ietf_encrypt(*itEncryptedData,NULL,subPack,subPack.len(),NULL,0,NULL,(unsigned char *)"\x00\x00\x00\x00PS-Msg06",sessionKey);
                                                   
      LOG2("---------- END SUB-TLVS! ----------\n");
      
      tlvRespond(responseTLV);                              // send response to client

      delete srp;                                           // delete SRP - no longer needed once pairing is completed

      mdns_service_txt_item_set("_hap","_tcp","sf","0");    // broadcast new status
      
      LOG1("\n*** ACCESSORY PAIRED! ***\n");

      STATUS_UPDATE(on(),HS_PAIRED)      
            
      if(homeSpan.pairCallback)                             // if set, invoke user-defined Pairing Callback to indicate device has been paired
        homeSpan.pairCallback(true);
      
      return(1);        
    }       
    break;

  } // switch

  return(1);

} // postPairSetup

//////////////////////////////////////

int HAPClient::postPairVerifyURL(uint8_t *content, size_t len){

  HAPTLV iosTLV;
  HAPTLV responseTLV;
  HAPTLV subTLV;

  iosTLV.unpack(content,len);
  if(homeSpan.getLogLevel()>1)
    iosTLV.print();
  LOG2("------------ END TLVS! ------------\n");

  LOG1("In Pair Verify #%d (%s)...",conNum,client.remoteIP().toString().c_str());
  
  auto itState=iosTLV.find(kTLVType_State);

  if(iosTLV.len(itState)!=1){                                   // missing STATE TLV
    LOG0("\n*** ERROR: Missing or invalid 'State' TLV\n\n");
    badRequestError();                                          // return with 400 error, which closes connection      
    return(0);
  }

  int tlvState=(*itState)[0];

  if(!nAdminControllers()){                             // error: Device not yet paired - we should not be receiving any requests for Pair-Verify!
    LOG0("\n*** ERROR: Device not yet paired!\n\n");
    responseTLV.add(kTLVType_State,tlvState+1);         // set response STATE to requested state+1 (which should match the state that was expected by the controller)
    responseTLV.add(kTLVType_Error,tagError_Unknown);   // set Error=Unknown
    tlvRespond(responseTLV);                            // send response to client
    return(0);
  };

  LOG2("Found <M%d>\n",tlvState);          // unlike pair-setup, out-of-sequencing can be handled gracefully for pair-verify (HAP requirement). No need to keep track of pairStatus

  switch(tlvState){                        // Pair-Verify STATE received -- process request!  (HAP Section 5.7)

    case pairState_M1:{                    // 'Verify Start Request'

      auto itPublicKey=iosTLV.find(kTLVType_PublicKey);

      if(iosTLV.len(itPublicKey)!=crypto_box_PUBLICKEYBYTES){            
        LOG0("\n*** ERROR: Required 'PublicKey' TLV record for this step is bad or missing\n\n");
        responseTLV.add(kTLVType_State,pairState_M2);        // set State=<M2>
        responseTLV.add(kTLVType_Error,tagError_Unknown);    // set Error=Unknown (there is no specific error type for missing/bad TLV data)
        tlvRespond(responseTLV);                             // send response to client
        return(0);        
      }

      publicCurveKey=(uint8_t *)HS_MALLOC(crypto_box_PUBLICKEYBYTES);               // temporary space - will be deleted at end of verification process
      TempBuffer<uint8_t> secretCurveKey(crypto_box_SECRETKEYBYTES);                // temporary space - used only in this block     
      crypto_box_keypair(publicCurveKey,secretCurveKey);                            // generate Accessory's random Curve25519 Public/Secret Key Pair

      iosCurveKey=(uint8_t *)HS_MALLOC(crypto_box_PUBLICKEYBYTES);                  // temporary space - will be deleted at end of verification process
      memcpy(iosCurveKey,*itPublicKey,crypto_box_PUBLICKEYBYTES);                   // save Controller's Curve25519 Public Key
            
      // concatenate Accessory's Curve25519 Public Key, Accessory's Pairing ID, and Controller's Curve25519 Public Key into accessoryInfo
      
      TempBuffer<uint8_t> accessoryInfo(publicCurveKey,crypto_box_PUBLICKEYBYTES,accessory.ID,hap_accessory_IDBYTES,iosCurveKey,crypto_box_PUBLICKEYBYTES,NULL);

      subTLV.add(kTLVType_Identifier,hap_accessory_IDBYTES,accessory.ID);                         // set Identifier subTLV record as Accessory's Pairing ID
      auto itSignature=subTLV.add(kTLVType_Signature,crypto_sign_BYTES,NULL);                     // create blank Signature subTLV
      crypto_sign_detached(*itSignature,NULL,accessoryInfo,accessoryInfo.len(),accessory.LTSK);   // produce Signature of accessoryInfo using Accessory's LTSK

      LOG2("------- ENCRYPTING SUB-TLVS -------\n");

      if(homeSpan.getLogLevel()>1)
        subTLV.print();

      TempBuffer<uint8_t> subPack(subTLV.pack_size());                                                    // create sub-TLV by packing Identifier and Signature TLV records together
      subTLV.pack(subPack);                                

      sharedCurveKey=(uint8_t *)HS_MALLOC(crypto_box_PUBLICKEYBYTES);                                     // temporary space - will be deleted at end of verification process
      crypto_scalarmult_curve25519(sharedCurveKey,secretCurveKey,iosCurveKey);                            // generate Shared-Secret Curve25519 Key from Accessory's Curve25519 Secret Key and Controller's Curve25519 Public Key

      sessionKey=(uint8_t *)HS_MALLOC(crypto_box_PUBLICKEYBYTES);                                                                // temporary space - will be deleted at end of verification process
      hkdf.create(sessionKey,sharedCurveKey,crypto_box_PUBLICKEYBYTES,"Pair-Verify-Encrypt-Salt","Pair-Verify-Encrypt-Info");    // create Session Curve25519 Key from Shared-Secret Curve25519 Key using HKDF-SHA-512  

      auto itEncryptedData=responseTLV.add(kTLVType_EncryptedData,subPack.len()+crypto_aead_chacha20poly1305_IETF_ABYTES,NULL);                                    // create blank EncryptedData subTLV
      crypto_aead_chacha20poly1305_ietf_encrypt(*itEncryptedData,NULL,subPack,subPack.len(),NULL,0,NULL,(unsigned char *)"\x00\x00\x00\x00PV-Msg02",sessionKey);   // encrypt data with Session Curve25519 Key and padded nonce="PV-Msg02"
                                            
      LOG2("---------- END SUB-TLVS! ----------\n");
      
      responseTLV.add(kTLVType_State,pairState_M2);                                        // set State=<M2>
      responseTLV.add(kTLVType_PublicKey,crypto_box_PUBLICKEYBYTES,publicCurveKey);        // set PublicKey to Accessory's Curve25519 Public Key
    
      tlvRespond(responseTLV);                                      // send response to client  
    }
    break;  
   
    case pairState_M3:{                     // 'Verify Finish Request'

      auto itEncryptedData=iosTLV.find(kTLVType_EncryptedData);

      if(iosTLV.len(itEncryptedData)<=0){            
        LOG0("\n*** ERROR: Required 'EncryptedData' TLV record for this step is bad or missing\n\n");
        responseTLV.add(kTLVType_State,pairState_M4);               // set State=<M4>
        responseTLV.add(kTLVType_Error,tagError_Unknown);           // set Error=Unknown (there is no specific error type for missing/bad TLV data)
        tlvRespond(responseTLV);                                    // send response to client
        return(0);
      };

      LOG2("------- DECRYPTING SUB-TLVS -------\n");

      // use Session Curve25519 Key (from previous step) to decrypt encrypytedData TLV with padded nonce="PV-Msg03"

      TempBuffer<uint8_t> decrypted((*itEncryptedData).len-crypto_aead_chacha20poly1305_IETF_ABYTES);        // temporary storage for decrypted data
      
      if(crypto_aead_chacha20poly1305_ietf_decrypt(decrypted, NULL, NULL, *itEncryptedData, (*itEncryptedData).len, NULL, 0, (unsigned char *)"\x00\x00\x00\x00PV-Msg03", sessionKey)==-1){          
        LOG0("\n*** ERROR: Verify Authentication Failed\n\n");
        responseTLV.add(kTLVType_State,pairState_M4);               // set State=<M4>
        responseTLV.add(kTLVType_Error,tagError_Authentication);    // set Error=Authentication
        tlvRespond(responseTLV);                                    // send response to client
        return(0);        
      }

      subTLV.unpack(decrypted,decrypted.len());                     // unpack TLV     
      if(homeSpan.getLogLevel()>1)
        subTLV.print();                                             // print decrypted TLV data
      
      LOG2("---------- END SUB-TLVS! ----------\n");

      auto itIdentifier=subTLV.find(kTLVType_Identifier);
      auto itSignature=subTLV.find(kTLVType_Signature);

      if(subTLV.len(itIdentifier)!=hap_controller_IDBYTES || subTLV.len(itSignature)!=crypto_sign_BYTES){ 
        LOG0("\n*** ERROR: One or more of required 'Identifier,' and 'Signature' TLV records for this step is bad or missing\n\n");
        responseTLV.add(kTLVType_State,pairState_M4);               // set State=<M4>
        responseTLV.add(kTLVType_Error,tagError_Unknown);           // set Error=Unknown (there is no specific error type for missing/bad TLV data)
        tlvRespond(responseTLV);                                    // send response to client
        return(0);
      }

      Controller *tPair;                                            // temporary pointer to Controller
      
      if(!(tPair=findController(*itIdentifier))){
        LOG0("\n*** ERROR: Unrecognized Controller ID: ");
        charPrintRow(*itIdentifier,hap_controller_IDBYTES,2);
        LOG0("\n\n");
        responseTLV.add(kTLVType_State,pairState_M4);               // set State=<M4>
        responseTLV.add(kTLVType_Error,tagError_Authentication);    // set Error=Authentication
        tlvRespond(responseTLV);                                    // send response to client
        return(0);
      }

      LOG2("\n*** Verifying session with Controller ID: ");
      charPrintRow(tPair->ID,hap_controller_IDBYTES,2);
      LOG2("...\n");

      // concatenate Controller's Curve25519 Public Key (from previous step), Controller's Pairing ID, and Accessory's Curve25519 Public Key (from previous step) into iosDeviceInfo     

      TempBuffer<uint8_t> iosDeviceInfo(iosCurveKey,crypto_box_PUBLICKEYBYTES,tPair->ID,hap_controller_IDBYTES,publicCurveKey,crypto_box_PUBLICKEYBYTES,NULL);
      
      if(crypto_sign_verify_detached(*itSignature, iosDeviceInfo, iosDeviceInfo.len(), tPair->LTPK) != 0){         // verify signature of iosDeviceInfo using Controller's LTPK   
        LOG0("\n*** ERROR: LPTK Signature Verification Failed\n\n");
        responseTLV.add(kTLVType_State,pairState_M4);               // set State=<M4>
        responseTLV.add(kTLVType_Error,tagError_Authentication);    // set Error=Authentication
        tlvRespond(responseTLV);                                    // send response to client
        return(0);                
      }

      responseTLV.add(kTLVType_State,pairState_M4);                 // set State=<M4>
      tlvRespond(responseTLV);                                      // send response to client (unencrypted since cPair=NULL)

      cPair=tPair;        // save Controller for this connection slot - connection is now verified and should be encrypted going forward

      hkdf.create(a2cKey,sharedCurveKey,32,"Control-Salt","Control-Read-Encryption-Key");        // create AccessoryToControllerKey from (previously-saved) Shared-Secret Curve25519 Key (HAP Section 6.5.2)
      hkdf.create(c2aKey,sharedCurveKey,32,"Control-Salt","Control-Write-Encryption-Key");       // create ControllerToAccessoryKey from (previously-saved) Shared-Secret Curve25519 Key (HAP Section 6.5.2)
      
      a2cNonce.zero();         // reset Nonces for this session to zero
      c2aNonce.zero();

      free(publicCurveKey);     // free storage of these temporary variables created in previous step
      free(sharedCurveKey);
      free(sessionKey);
      free(iosCurveKey);

      LOG2("\n*** SESSION VERIFICATION COMPLETE *** \n");
    }
    break;
  
  } // switch

  return(1);
  
} // postPairVerify

//////////////////////////////////////

int HAPClient::postPairingsURL(uint8_t *content, size_t len){

  if(!cPair){                       // unverified, unencrypted session
    unauthorizedError();
    return(0);
  }

  HAPTLV iosTLV;
  HAPTLV responseTLV;

  iosTLV.unpack(content,len);
  if(homeSpan.getLogLevel()>1)
    iosTLV.print();
  LOG2("------------ END TLVS! ------------\n");

  LOG1("In Post Pairings #%d (%s)...",conNum,client.remoteIP().toString().c_str());
  
  auto itState=iosTLV.find(kTLVType_State);
  auto itMethod=iosTLV.find(kTLVType_Method);
    
  if(iosTLV.len(itState)!=1 || (*itState)[0]!=1){               // missing STATE TLV
    LOG0("\n*** ERROR: Parirings 'State' is either missing or not set to <M1>\n\n");
    badRequestError();                                          // return with 400 error, which closes connection      
    return(0);
  }

  if(iosTLV.len(itMethod)!=1){                                  // missing METHOD TLV
    LOG0("\n*** ERROR: Missing or invalid 'Method' TLV\n\n");
    badRequestError();                                          // return with 400 error, which closes connection      
    return(0);
  }

  int tlvMethod=(*itMethod)[0];

  responseTLV.add(kTLVType_State,pairState_M2);                 // all responses include State=M2
  
  switch(tlvMethod){                        // List-Pairings received -- process request!  (HAP Sections 5.10-5.12)

    case 3: {
      LOG1("Add...\n");

      auto itIdentifier=iosTLV.find(kTLVType_Identifier);
      auto itPublicKey=iosTLV.find(kTLVType_PublicKey);
      auto itPermissions=iosTLV.find(kTLVType_Permissions);
      
      if(iosTLV.len(itIdentifier)!=hap_controller_IDBYTES || iosTLV.len(itPublicKey)!=crypto_sign_PUBLICKEYBYTES || iosTLV.len(itPermissions)!=1){            
        LOG0("\n*** ERROR: One or more of required 'Identifier,' 'PublicKey,' and 'Permissions' TLV records for this step is bad or missing\n\n");
        responseTLV.add(kTLVType_Error,tagError_Unknown);
        tlvRespond(responseTLV);
        return(0);
      }
      
      if(!cPair->admin){
        LOG0("\n*** ERROR: Controller making request does not have admin privileges to add/update other Controllers\n\n");
        responseTLV.add(kTLVType_Error,tagError_Authentication);
        tlvRespond(responseTLV);
        return(0);
      } 
             
      tagError err=addController(*itIdentifier,*itPublicKey,(*itPermissions)[0]);
      if(err!=tagError_None)
        responseTLV.add(kTLVType_Error,err);
      
      tlvRespond(responseTLV);
      return(1);
    }
    break;

    case 4: {
      LOG1("Remove...\n");

      auto itIdentifier=iosTLV.find(kTLVType_Identifier);

      if(iosTLV.len(itIdentifier)!=hap_controller_IDBYTES){            
        LOG0("\n*** ERROR: Required 'Identifier' TLV record for this step is bad or missing\n\n");
        responseTLV.add(kTLVType_Error,tagError_Unknown);
        tlvRespond(responseTLV);
        return(0);
      }
      
      if(!cPair->admin){
        LOG0("\n*** ERROR: Controller making request does not have admin privileges to remove Controllers\n\n");
        responseTLV.add(kTLVType_Error,tagError_Authentication);
        tlvRespond(responseTLV);
        return(0);
      }
      
      tlvRespond(responseTLV);           // must send response before removing Controller     
      removeController(*itIdentifier);
      
      return(1);
    } 
    break;
      
    case 5: {
      LOG1("List...\n");

      if(!cPair->admin){
        LOG0("\n*** ERROR: Controller making request does not have admin privileges to remove Controllers\n\n");
        responseTLV.add(kTLVType_Error,tagError_Authentication);
        tlvRespond(responseTLV);
        return(0);
      }      

      boolean addSeparator=false;
      
      for(auto it=controllerList.begin();it!=controllerList.end();it++){
        if((*it).allocated){
          if(addSeparator)         
            responseTLV.add(kTLVType_Separator);                                        
          responseTLV.add(kTLVType_Permissions,(*it).admin);      
          responseTLV.add(kTLVType_Identifier,hap_controller_IDBYTES,(*it).ID);
          responseTLV.add(kTLVType_PublicKey,crypto_sign_PUBLICKEYBYTES,(*it).LTPK);
          addSeparator=true;
        }
      }

      tlvRespond(responseTLV);
      return(1);
    }
    break;

    default: {
      LOG0("\n*** ERROR: Undefined List-Pairings Method: %d.  Must be 3, 4, or 5\n\n",tlvMethod);
      badRequestError();                                    // return with 400 error, which closes connection      
      return(0);
    }
  } // switch
  
  return(1);
}

//////////////////////////////////////

int HAPClient::getAccessoriesURL(){

  if(!cPair){                       // unverified, unencrypted session
    unauthorizedError();
    return(0);
  }

  LOG1("In Get Accessories #%d (%s)...\n",conNum,client.remoteIP().toString().c_str());

  homeSpan.printfAttributes();
  size_t nBytes=hapOut.getSize();
  hapOut.flush();

  LOG2("\n>>>>>>>>>> %s >>>>>>>>>>\n",client.remoteIP().toString().c_str());

  hapOut.setLogLevel(2).setHapClient(this);    
  hapOut << "HTTP/1.1 200 OK\r\nContent-Type: application/hap+json\r\nContent-Length: " << nBytes << "\r\n\r\n";
  homeSpan.printfAttributes();
  hapOut.flush();

  LOG2("\n-------- SENT ENCRYPTED! --------\n");
         
  return(1);
  
} // getAccessories

//////////////////////////////////////

int HAPClient::getCharacteristicsURL(char *urlBuf){

  if(!cPair){                       // unverified, unencrypted session
    unauthorizedError();
    return(0);
  }

  LOG1("In Get Characteristics #%d (%s)...\n",conNum,client.remoteIP().toString().c_str());

  int len=strlen(urlBuf);           // determine number of IDs specified by counting commas in URL
  int numIDs=1;
  for(int i=0;i<len;i++)
    if(urlBuf[i]==',')
      numIDs++;
  
  TempBuffer<char *> ids(numIDs);   // reserve space for number of IDs found
  int flags=GET_VALUE|GET_AID;      // flags indicating which characteristic fields to include in response (HAP Table 6-13)
  numIDs=0;                         // reset number of IDs found

  char *lastSpace=strchr(urlBuf,' ');
  if(lastSpace)
    lastSpace[0]='\0';
    
  char *p1;
  while(char *t1=strtok_r(urlBuf,"&",&p1)){      // parse request into major tokens
    urlBuf=NULL;

    if(!strcmp(t1,"meta=1")){
      flags|=GET_META;
    } else 
    if(!strcmp(t1,"perms=1")){
      flags|=GET_PERMS;
    } else 
    if(!strcmp(t1,"type=1")){
      flags|=GET_TYPE;
    } else 
    if(!strcmp(t1,"ev=1")){
      flags|=GET_EV;
    } else
    if(!strncmp(t1,"id=",3)){   
      t1+=3;
      char *p2;
      while(char *t2=strtok_r(t1,",",&p2)){      // parse IDs
        t1=NULL;
        ids[numIDs++]=t2;
      }
    }
  } // parse URL

  if(!numIDs)           // could not find any IDs
    return(0);

  boolean statusFlag=homeSpan.printfAttributes(ids,numIDs,flags);     // get statusFlag returned to use below
  size_t nBytes=hapOut.getSize();
  hapOut.flush();

  hapOut.setLogLevel(2).setHapClient(this);
  hapOut << "HTTP/1.1 " << (!statusFlag?"200 OK":"207 Multi-Status") << "\r\nContent-Type: application/hap+json\r\nContent-Length: " << nBytes << "\r\n\r\n";
  homeSpan.printfAttributes(ids,numIDs,flags);
  hapOut.flush();

  LOG2("\n-------- SENT ENCRYPTED! --------\n");
        
  return(1);
}

//////////////////////////////////////

int HAPClient::putCharacteristicsURL(char *json){

  if(!cPair){                       // unverified, unencrypted session
    unauthorizedError();
    return(0);
  }

  LOG1("In Put Characteristics #%d (%s)...\n",conNum,client.remoteIP().toString().c_str());

  int n=homeSpan.countCharacteristics(json);    // count number of objects in JSON request
  if(n==0)                                      // if no objects found, return
    return(0);
 
  SpanBuf pObj[n];                                        // reserve space for objects
  if(!homeSpan.updateCharacteristics(json, pObj))         // perform update
    return(0);                                            // return if failed to update (error message will have been printed in update)

  int multiCast=0;                                        // check if all status is OK, or if multicast response is request
  for(int i=0;i<n;i++)
    if(pObj[i].status!=StatusCode::OK)
      multiCast=1;    

  LOG2("\n>>>>>>>>>> %s >>>>>>>>>>\n",client.remoteIP().toString().c_str());

  if(!multiCast){                                         // JSON object has no content

    hapOut.setLogLevel(2).setHapClient(this);    
    hapOut << "HTTP/1.1 204 No Content\r\n\r\n";
    hapOut.flush();
        
  } else {                                                // multicast respose is required

    homeSpan.printfAttributes(pObj,n);
    size_t nBytes=hapOut.getSize();
    hapOut.flush();
  
    hapOut.setLogLevel(2).setHapClient(this);
    hapOut << "HTTP/1.1 207 Multi-Status\r\nContent-Type: application/hap+json\r\nContent-Length: " << nBytes << "\r\n\r\n";
    homeSpan.printfAttributes(pObj,n);
    hapOut.flush(); 
  }

  LOG2("\n-------- SENT ENCRYPTED! --------\n");

  // Create and send Event Notifications if needed

  eventNotify(pObj,n,HAPClient::conNum);                  // transmit EVENT Notification for "n" pObj objects, except DO NOT notify client making request
    
  return(1);
}

//////////////////////////////////////

int HAPClient::putPrepareURL(char *json){

  if(!cPair){                       // unverified, unencrypted session
    unauthorizedError();
    return(0);
  }

  LOG1("In Put Prepare #%d (%s)...\n",conNum,client.remoteIP().toString().c_str());

  char ttlToken[]="\"ttl\":";
  char pidToken[]="\"pid\":";
  
  char *cBuf;
  uint32_t ttl;
  uint64_t pid;
   
  if((cBuf=strstr(json,ttlToken)))
    sscanf(cBuf+strlen(ttlToken),"%u",&ttl);

  if((cBuf=strstr(json,pidToken)))
    sscanf(cBuf+strlen(ttlToken),"%llu",&pid);

  StatusCode status=StatusCode::OK;

  if(ttl>0 && pid>0){                           // found required elements
    homeSpan.TimedWrites[pid]=ttl+millis();     // store this pid/alarmTime combination 
  } else {                                      // problems parsing request
    status=StatusCode::InvalidValue;
  }

  LOG2("\n>>>>>>>>>> %s >>>>>>>>>>\n",client.remoteIP().toString().c_str());

  hapOut << "{\"status\":" << (int)status << "}";
  size_t nBytes=hapOut.getSize();
  hapOut.flush();

  hapOut.setLogLevel(2).setHapClient(this);    
  hapOut << "HTTP/1.1 200 OK\r\nContent-Type: application/hap+json\r\nContent-Length: " << nBytes << "\r\n\r\n";
  hapOut << "{\"status\":" << (int)status << "}";
  hapOut.flush();

  LOG2("\n-------- SENT ENCRYPTED! --------\n");
         
  return(1);
}

//////////////////////////////////////

void HAPClient::getStatusURL(HAPClient *hapClient, void (*callBack)(const char *, void *), void *user_data){
  
  char clocktime[33];

  if(homeSpan.webLog.timeInit){
    struct tm timeinfo;
    getLocalTime(&timeinfo,10);
    strftime(clocktime,sizeof(clocktime),"%c",&timeinfo);
  } else {
    sprintf(clocktime,"Unknown");        
  }

  char uptime[32];
  int seconds=esp_timer_get_time()/1e6;
  int secs=seconds%60;
  int mins=(seconds/=60)%60;
  int hours=(seconds/=60)%24;
  int days=(seconds/=24);
    
  sprintf(uptime,"%d:%02d:%02d:%02d",days,hours,mins,secs);

  if(hapClient)
    LOG2("\n>>>>>>>>>> %s >>>>>>>>>>\n",hapClient->client.remoteIP().toString().c_str());
    
  hapOut.setHapClient(hapClient).setLogLevel(2).setCallback(callBack).setCallbackUserData(user_data);

  if(!callBack)
    hapOut << "HTTP/1.1 200 OK\r\nContent-type: text/html; charset=utf-8\r\n\r\n";
    
  hapOut << "<html><head><title>" << homeSpan.displayName << "</title><meta http-equiv=\"refresh\" content=\"30\" >\n";
  hapOut << "<style>body {background-color:lightblue;} th, td {padding-right: 10px; padding-left: 10px; border:1px solid black;}" << homeSpan.webLog.css.c_str() << "</style></head>\n";
  hapOut << "<body class=bod1><CENTER>";
  hapOut << "<img src=\"data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAfQAAAC5CAYAAADeZ82MAAAACXBIWXMAAAsTAAALEwEAmpwYAAAHCGlUWHRYTUw6Y29tLmFkb2JlLnhtcAAAAAAAPD94cGFja2V0IGJlZ2luPSLvu78iIGlkPSJXNU0wTXBDZWhpSHpyZVN6TlRjemtjOWQiPz4gPHg6eG1wbWV0YSB4bWxuczp4PSJhZG9iZTpuczptZXRhLyIgeDp4bXB0az0iQWRvYmUgWE1QIENvcmUgOS4xLWMwMDIgNzkuYTZhNjM5NjhhLCAyMDI0LzAzLzA2LTExOjUyOjA1ICAgICAgICAiPiA8cmRmOlJERiB4bWxuczpyZGY9Imh0dHA6Ly93d3cudzMub3JnLzE5OTkvMDIvMjItcmRmLXN5bnRheC1ucyMiPiA8cmRmOkRlc2NyaXB0aW9uIHJkZjphYm91dD0iIiB4bWxuczp4bXA9Imh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC8iIHhtbG5zOmRjPSJodHRwOi8vcHVybC5vcmcvZGMvZWxlbWVudHMvMS4xLyIgeG1sbnM6cGhvdG9zaG9wPSJodHRwOi8vbnMuYWRvYmUuY29tL3Bob3Rvc2hvcC8xLjAvIiB4bWxuczp4bXBNTT0iaHR0cDovL25zLmFkb2JlLmNvbS94YXAvMS4wL21tLyIgeG1sbnM6c3RFdnQ9Imh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC9zVHlwZS9SZXNvdXJjZUV2ZW50IyIgeG1wOkNyZWF0b3JUb29sPSJBZG9iZSBQaG90b3Nob3AgMjUuNSAoTWFjaW50b3NoKSIgeG1wOkNyZWF0ZURhdGU9IjIwMjQtMDMtMTNUMDk6MzY6MTQtMDQ6MDAiIHhtcDpNb2RpZnlEYXRlPSIyMDI0LTA2LTEyVDA5OjIwOjA0LTA0OjAwIiB4bXA6TWV0YWRhdGFEYXRlPSIyMDI0LTA2LTEyVDA5OjIwOjA0LTA0OjAwIiBkYzpmb3JtYXQ9ImltYWdlL3BuZyIgcGhvdG9zaG9wOkNvbG9yTW9kZT0iMyIgeG1wTU06SW5zdGFuY2VJRD0ieG1wLmlpZDo0NDc3OTlhNi0wOThmLTRjN2QtODIyNy0yMjNlNmYxM2M0YmUiIHhtcE1NOkRvY3VtZW50SUQ9ImFkb2JlOmRvY2lkOnBob3Rvc2hvcDo1NGI1OGZlYS02YzNiLTJiNDctYWYxZi0wMTgwOTgwYjE0NDIiIHhtcE1NOk9yaWdpbmFsRG9jdW1lbnRJRD0ieG1wLmRpZDpkM2VjNGIxZC00NDRiLTRiZDUtYmRhZi01M2ZiZDE5N2Y4YWYiPiA8eG1wTU06SGlzdG9yeT4gPHJkZjpTZXE+IDxyZGY6bGkgc3RFdnQ6YWN0aW9uPSJjcmVhdGVkIiBzdEV2dDppbnN0YW5jZUlEPSJ4bXAuaWlkOmQzZWM0YjFkLTQ0NGItNGJkNS1iZGFmLTUzZmJkMTk3ZjhhZiIgc3RFdnQ6d2hlbj0iMjAyNC0wMy0xM1QwOTozNjoxNC0wNDowMCIgc3RFdnQ6c29mdHdhcmVBZ2VudD0iQWRvYmUgUGhvdG9zaG9wIDI1LjUgKE1hY2ludG9zaCkiLz4gPHJkZjpsaSBzdEV2dDphY3Rpb249ImNvbnZlcnRlZCIgc3RFdnQ6cGFyYW1ldGVycz0iZnJvbSBhcHBsaWNhdGlvbi92bmQuYWRvYmUucGhvdG9zaG9wIHRvIGltYWdlL3BuZyIvPiA8cmRmOmxpIHN0RXZ0OmFjdGlvbj0ic2F2ZWQiIHN0RXZ0Omluc3RhbmNlSUQ9InhtcC5paWQ6MmE4OTdlMzQtOTk3YS00MTMwLThkNzctZjQ1ZThkZTAyMjdkIiBzdEV2dDp3aGVuPSIyMDI0LTAzLTEzVDA5OjQ5OjQ3LTA0OjAwIiBzdEV2dDpzb2Z0d2FyZUFnZW50PSJBZG9iZSBQaG90b3Nob3AgMjUuNSAoTWFjaW50b3NoKSIgc3RFdnQ6Y2hhbmdlZD0iLyIvPiA8cmRmOmxpIHN0RXZ0OmFjdGlvbj0ic2F2ZWQiIHN0RXZ0Omluc3RhbmNlSUQ9InhtcC5paWQ6NDQ3Nzk5YTYtMDk4Zi00YzdkLTgyMjctMjIzZTZmMTNjNGJlIiBzdEV2dDp3aGVuPSIyMDI0LTA2LTEyVDA5OjIwOjA0LTA0OjAwIiBzdEV2dDpzb2Z0d2FyZUFnZW50PSJBZG9iZSBQaG90b3Nob3AgMjUuOSAoTWFjaW50b3NoKSIgc3RFdnQ6Y2hhbmdlZD0iLyIvPiA8L3JkZjpTZXE+IDwveG1wTU06SGlzdG9yeT4g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UFvK+P9+26qHfowr9LUGbimBeGSeK5udCGWN9KT0xhDohzGI4rKTtd4HffiQVeSUTFS6NRH7YsySdsgTBfIhcciZXS1iIIcxoCsQ+0M5yI+Q/KA2R9Kin0Ly6ceHDGGE/BdS2Wl//UlW6IXlXh8yRzr3/FQG9OkBdjwE9FLBFQb+WUdavVWf75hVvQtjax8hkaaONtAdtwG96kvDUTLvq+v1/oqZflTkxcko3NEQUF9QoQZlvSDf71vyvXn/8XJfyvSSFmygvRCs6356kuhO7prT7wGI2+Q+a9WmjKMzm2sP9B0Cug3qtArox3r93y8KM1Cm3MhAGAe4BSGTGZRZacU1pyZSJCZ7JMaFzZDHvboweqlTCdSUJKL87BQWn/a9x9cOIytTYPcpMw3OGvJCdE1Ab0hxS2z6HRj2Y/Afn44nWaHvNId+yRHA5E9ZQJ+8/vES0MuBX5Kiox2TKp9vGCuroPgnXck9wRz6EbPpj9eAfiwq3x2Sg03SpAD57y/gyHgh9fX/42MdcI93yH0poAJjDx1mRi3pIJ18//R4iykYD+PAVDC6x/PbRfNDrUhNKPatgv9x2wpyP8YBvZtEsDmNoRDWSpW6ptDI980+nrfH6ru8Rte17EiBYp9IkFW/u7DlMYRqtKx+Z51SBpl+tOrBF9JeRghC6CpDF1FIeUvpYxKVKX2i2CQTSzPvNSP+SCr06uulL/ekCVRPkVJcHdDredvjIaDXqmtlbeb3dssRvN7FVcCYrqMWllmoYI9UcOV4DejTtky9jnQsbKrsxlFU50sTAmUdNRnyeA7oyaNjoUCppoKZnfTzarqcfwNRugrmNew+DfrjWFtKACrFWdSVAL+q0I/5+p8vXmtKYeXxr2J76uJZbifoWhDidJ/EqrJOkTaUirzLdqoeA+6YwW0PO6fO9IZRNnaSc1X+3h0EXd0PAdoYx3EO3dGDIlzpsY+Vf04IZruz7TfVm16Cd3/9FwroBbK7sz7UJ1De+59kQP/DHYLRLUdYzfzRwvv7I0Zy19FAxtceyfv6PxSYptfx/Uc4N/6HVTV458LXbzlC9vfi3jkOrxtHew2rQFmkX+88Cpi87Dt2SHpvOcrPfzEjEfC42td/9vJx9nZqTuUFl+oaBQ0OM1OtmsA8PRuV1GSGar5bb2um+jhVrtrLS/2Pb64q9NVardVardVardVaBfTVWq3VWq3VWq3VWgX01Vqt1Vqt1VqtVUBfrdVardVardVarVVAX63VWq3VWq3VWq1VQF+t1Vqt1Vqt1VqtVUBfrdVardVardVaBfTVWq3VWq3VWq3VWgX01Vqt1Vqt1Vqt1VoF9NVardVardVardVaBfTVWq3VWq3VWq3VWgX01Vqt1Vqt1Vqt/wzr/wNaJrHADimtHgAAAABJRU5ErkJggg==\" />";
  hapOut << "<P>\n";
  
  hapOut << "<table class=tab1>\n";
  hapOut << "<tr><td>Up Time:</td><td>" << uptime << "</td>\n";
  hapOut << "<td>Current Time:</td><td>" << clocktime << "</td>\n";
  hapOut << "<td>Boot Time:</td><td>" << homeSpan.webLog.bootTime << "</td></tr>\n"; 
  hapOut << "<tr><td>Reset Reason:</td><td>";
  
  switch(esp_reset_reason()) {
    case ESP_RST_UNKNOWN:
      hapOut << "Cannot be determined";
      break;
    case ESP_RST_POWERON:
      hapOut << "Power-on event";
      break;
    case ESP_RST_EXT:
      hapOut << "External pin";
      break;
    case ESP_RST_SW:
      hapOut << "Software reboot via esp_restart";
      break;
    case ESP_RST_PANIC:
      hapOut << "Software Exception/Panic";
      break;
    case ESP_RST_INT_WDT:
      hapOut << "Interrupt watchdog";
      break;
    case ESP_RST_TASK_WDT:
      hapOut << "Task watchdog";
      break;
    case ESP_RST_WDT:
      hapOut << "Other watchdogs";
      break;
    case ESP_RST_DEEPSLEEP:
      hapOut << "Exiting deep sleep mode";
      break;
    case ESP_RST_BROWNOUT:
      hapOut << "Brownout";
      break;
    case ESP_RST_SDIO:
      hapOut << "SDIO";
      break;
    default:
      hapOut << "Unknown Reset Code";
  }
  
  hapOut << " (" << esp_reset_reason() << ")</td>\n";
  
  hapOut << "<td>HomeKit Status:</td><td>" << (HAPClient::nAdminControllers()?"PAIRED":"NOT PAIRED") << "</td>\n";   
  hapOut << "<td>Max Log Entries:</td><td>" << homeSpan.webLog.maxEntries << "</td></tr>\n"; 

  if(homeSpan.weblogCallback){
    String usrString;
    homeSpan.weblogCallback(usrString); // Callback to add user-defined html in top table.
    hapOut << usrString.c_str();    
  }
    
  hapOut << "</table>\n";
  hapOut << "<p></p>";
  
  if(homeSpan.webLog.maxEntries>0){
    hapOut << "<table class=tab2><tr><th>Entry</th><th>Up Time</th><th>GMT Log Time</th><th>Message</th></tr>\n";
    int lastIndex=homeSpan.webLog.nEntries-homeSpan.webLog.maxEntries;
    if(lastIndex<0)
      lastIndex=0;
    
    for(int i=homeSpan.webLog.nEntries-1;i>=lastIndex;i--){
      int index=i%homeSpan.webLog.maxEntries;
      seconds=homeSpan.webLog.log[index].upTime/1e6;
      secs=seconds%60;
      mins=(seconds/=60)%60;
      hours=(seconds/=60)%24;
      days=(seconds/=24);   
      sprintf(uptime,"%d:%02d:%02d:%02d",days,hours,mins,secs);

      if(homeSpan.webLog.log[index].clockTime.tm_year>0)
        strftime(clocktime,sizeof(clocktime),"%c",&homeSpan.webLog.log[index].clockTime);
      else
        sprintf(clocktime,"Unknown");        
      
      hapOut << "<tr><td>" << i+1 << "</td><td>" << uptime << "</td><td>" << clocktime << "</td><td>" << homeSpan.webLog.log[index].message << "</td></tr>\n";
    }
    hapOut << "</table>\n";

  hapOut << "<table class=tab1>\n";
  hapOut << "<tr><td>WiFi Disconnects:</td><td>" << homeSpan.connected/2 << "</td></tr>\n";
  hapOut << "<tr><td>WiFi Signal:</td><td>" << (int)WiFi.RSSI() << " dBm</td></tr>\n";
  hapOut << "<tr><td>WiFi Gateway:</td><td>" << WiFi.gatewayIP().toString().c_str() << "</td></tr>\n";
  hapOut << "<tr><td>ESP32 Board:</td><td>" << ARDUINO_BOARD << "</td></tr>\n";
  hapOut << "<tr><td>Arduino-ESP Version:</td><td>" << ARDUINO_ESP_VERSION << "</td></tr>\n";
  hapOut << "<tr><td>ESP-IDF Version:</td><td>" << ESP_IDF_VERSION_MAJOR << "." << ESP_IDF_VERSION_MINOR << "." << ESP_IDF_VERSION_PATCH << "</td></tr>\n";
  hapOut << "<tr><td>HomeSpan Version:</td><td>" << HOMESPAN_VERSION << "</td></tr>\n";
  hapOut << "<tr><td>Sketch Version:</td><td>" << homeSpan.getSketchVersion() << "</td></tr>\n"; 
  hapOut << "<tr><td>Sodium Version:</td><td>" << sodium_version_string() << " Lib " << sodium_library_version_major() << "." << sodium_library_version_minor() << "</td></tr>\n"; 

  char mbtlsv[64];
  mbedtls_version_get_string_full(mbtlsv);
  hapOut << "<tr><td>MbedTLS Version:</td><td>" << mbtlsv << "</td></tr>\n";
  


  }
 
  hapOut << "</CENTER></body></html>\n";
  hapOut.flush();

  if(hapClient){
    hapClient->client.stop();
    LOG2("------------ SENT! --------------\n");
  }
}

//////////////////////////////////////

void HAPClient::checkNotifications(){

  if(!homeSpan.Notifications.empty()){                                          // if there are Notifications to process    
    eventNotify(&homeSpan.Notifications[0],homeSpan.Notifications.size());      // transmit EVENT Notifications
    homeSpan.Notifications.clear();                                             // clear Notifications vector
  }
}

//////////////////////////////////////

void HAPClient::checkTimedWrites(){

  unsigned long cTime=millis();                                       // get current time

  auto tw=homeSpan.TimedWrites.begin();
  while(tw!=homeSpan.TimedWrites.end()){
    if(cTime>tw->second){                                             // timer has expired
       LOG2("Removing PID=%llu  ALARM=%u\n",tw->first,tw->second);
       tw=homeSpan.TimedWrites.erase(tw);
      }
    else
      tw++; 
  }
 
}

//////////////////////////////////////

void HAPClient::eventNotify(SpanBuf *pObj, int nObj, int ignoreClient){
  
  for(int cNum=0;cNum<homeSpan.maxConnections;cNum++){      // loop over all connection slots
    if(hap[cNum]->client && cNum!=ignoreClient){            // if there is a client connected to this slot and it is NOT flagged to be ignored (in cases where it is the client making a PUT request)

      homeSpan.printfNotify(pObj,nObj,cNum);                // create JSON (which may be of zero length if there are no applicable notifications for this cNum)
      size_t nBytes=hapOut.getSize();
      hapOut.flush();

      if(nBytes>0){                                         // if there ARE notifications to send to client cNum
        
        LOG2("\n>>>>>>>>>> %s >>>>>>>>>>\n",hap[cNum]->client.remoteIP().toString().c_str());

        hapOut.setLogLevel(2).setHapClient(hap[cNum]);    
        hapOut << "EVENT/1.0 200 OK\r\nContent-Type: application/hap+json\r\nContent-Length: " << nBytes << "\r\n\r\n";
        homeSpan.printfNotify(pObj,nObj,cNum);
        hapOut.flush();

        LOG2("\n-------- SENT ENCRYPTED! --------\n");
      }
    }
  }         
}

/////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////

void HAPClient::tlvRespond(TLV8 &tlv8){

  tlv8.osprint(hapOut);
  size_t nBytes=hapOut.getSize();
  hapOut.flush();
  
  char *body;
  asprintf(&body,"HTTP/1.1 200 OK\r\nContent-Type: application/pairing+tlv8\r\nContent-Length: %d\r\n\r\n",nBytes);      // create Body with Content Length = size of TLV data

  LOG2("\n>>>>>>>>>> %s >>>>>>>>>>\n",client.remoteIP().toString().c_str());
  LOG2(body);
  if(homeSpan.getLogLevel()>1)
    tlv8.print();

  hapOut.setHapClient(this);
  hapOut << body;
  tlv8.osprint(hapOut);
  hapOut.flush();

  if(!cPair)
    LOG2("------------ SENT! --------------\n");
  else
    LOG2("-------- SENT ENCRYPTED! --------\n");
  
} // tlvRespond

//////////////////////////////////////

int HAPClient::receiveEncrypted(uint8_t *httpBuf, int messageSize){

  uint8_t aad[2];
  int nBytes=0;

  while(client.read(aad,2)==2){    // read initial 2-byte AAD record

    int n=aad[0]+aad[1]*256;                // compute number of bytes expected in message after decoding

    if(nBytes+n>messageSize){      // exceeded maximum number of bytes allowed in plaintext message
      LOG0("\n\n*** ERROR:  Decrypted message of %d bytes exceeded maximum expected message length of %d bytes\n\n",nBytes+n,messageSize);
      return(0);
      }

    TempBuffer<uint8_t> tBuf(n+16);      // expected number of total bytes = n bytes in encoded message + 16 bytes for appended authentication tag      

    if(client.read(tBuf,tBuf.len())!=tBuf.len()){      
      LOG0("\n\n*** ERROR: Malformed encrypted message frame\n\n");
      return(0);      
    }                

    if(crypto_aead_chacha20poly1305_ietf_decrypt(httpBuf+nBytes, NULL, NULL, tBuf, tBuf.len(), aad, 2, c2aNonce.get(), c2aKey)==-1){
      LOG0("\n\n*** ERROR: Can't Decrypt Message\n\n");
      return(0);        
    }

    c2aNonce.inc();

    nBytes+=n;          // increment total number of bytes in plaintext message
    
  } // while

  return(nBytes);
    
} // receiveEncrypted

/////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////

void HAPClient::hexPrintColumn(uint8_t *buf, int n, int minLogLevel){

  if(homeSpan.logLevel<minLogLevel)
    return;
  
  for(int i=0;i<n;i++)
    Serial.printf("%d) %02X\n",i,buf[i]);
}

//////////////////////////////////////

void HAPClient::hexPrintRow(uint8_t *buf, int n, int minLogLevel){

  if(homeSpan.logLevel<minLogLevel)
    return;

  for(int i=0;i<n;i++)
    Serial.printf("%02X",buf[i]);
}

//////////////////////////////////////

void HAPClient::charPrintRow(uint8_t *buf, int n, int minLogLevel){

  if(homeSpan.logLevel<minLogLevel)
    return;
  
  for(int i=0;i<n;i++)
    Serial.printf("%c",buf[i]);
}

//////////////////////////////////////

Controller *HAPClient::findController(uint8_t *id){

  for(auto it=controllerList.begin();it!=controllerList.end();it++){
    if(!memcmp((*it).ID,id,hap_controller_IDBYTES))
      return(&*it);
  }

  return(NULL);       // no match
}

//////////////////////////////////////

int HAPClient::nAdminControllers(){

  int n=0;
  for(auto it=controllerList.begin();it!=controllerList.end();it++)
    n+=((*it).admin);
  return(n);
}

//////////////////////////////////////

tagError HAPClient::addController(uint8_t *id, uint8_t *ltpk, boolean admin){

  Controller *cTemp=findController(id);

  tagError err=tagError_None;
  
  if(!cTemp){                                            // new controller    
    if(controllerList.size()<MAX_CONTROLLERS){
      controllerList.emplace_back(id,ltpk,admin);        // create and store data
      LOG2("\n*** Added Controller: ");
      charPrintRow(id,hap_controller_IDBYTES,2);
      LOG2(admin?" (admin)\n\n":" (regular)\n\n");
      saveControllers();
    } else {
      LOG0("\n*** ERROR: Can't pair more than %d Controllers\n\n",MAX_CONTROLLERS);
      err=tagError_MaxPeers;
    }    
  } else if(!memcmp(ltpk,cTemp->LTPK,crypto_sign_PUBLICKEYBYTES)){   // existing controller with same LTPK
    LOG2("\n*** Updated Controller: ");
    charPrintRow(id,hap_controller_IDBYTES,2);
    LOG2(" from %s to %s\n\n",cTemp->admin?"(admin)":"(regular)",admin?"(admin)":"(regular)");
    cTemp->admin=admin;
    saveControllers();    
  } else {
    LOG0("\n*** ERROR: Invalid request to update the LTPK of an existing Controller\n\n");
    err=tagError_Unknown;    
  }

  return(err);
}          

//////////////////////////////////////

void HAPClient::removeController(uint8_t *id){

  auto it=std::find_if(controllerList.begin(), controllerList.end(), [id](const Controller& cTemp){return(!memcmp(cTemp.ID,id,hap_controller_IDBYTES));});

  if(it==controllerList.end()){
    LOG2("\n*** Request to Remove Controller Ignored - Controller Not Found: ");
    charPrintRow(id,hap_controller_IDBYTES,2);
    LOG2("\n");
    return;
  }

  LOG1("\n*** Removing Controller: ");
  charPrintRow((*it).ID,hap_controller_IDBYTES,2);
  LOG1((*it).admin?" (admin)\n":" (regular)\n");
  
  tearDown((*it).ID);         // teardown any connections using this Controller
  controllerList.erase(it);   // remove Controller

  if(!nAdminControllers()){   // no more admin Controllers
    
    LOG1("That was last Admin Controller!  Removing any remaining Regular Controllers and unpairing Accessory\n");    
    
    tearDown(NULL);                                              // teardown all remaining connections
    controllerList.clear();                                      // remove all remaining Controllers
    mdns_service_txt_item_set("_hap","_tcp","sf","1");           // set Status Flag = 1 (Table 6-8)
    STATUS_UPDATE(start(LED_PAIRING_NEEDED),HS_PAIRING_NEEDED)   // set optional Status LED
    if(homeSpan.pairCallback)                                    // if set, invoke user-defined Pairing Callback to indicate device has been un-paired
      homeSpan.pairCallback(false);    
  }

  saveControllers();
}

//////////////////////////////////////

void HAPClient::tearDown(uint8_t *id){
  
  for(int i=0;i<homeSpan.maxConnections;i++){     // loop over all connection slots
    if(hap[i]->client && (id==NULL || (hap[i]->cPair && !memcmp(id,hap[i]->cPair->ID,hap_controller_IDBYTES)))){
      LOG1("*** Terminating Client #%d\n",i);
      hap[i]->client.stop();
    }
  }
}

//////////////////////////////////////

void HAPClient::printControllers(int minLogLevel){

  if(homeSpan.logLevel<minLogLevel)
    return;

  if(controllerList.empty()){
    Serial.printf("No Paired Controllers\n");
    return;    
  }
  
  for(auto it=controllerList.begin();it!=controllerList.end();it++){
    Serial.printf("Paired Controller: ");
    charPrintRow((*it).ID,hap_controller_IDBYTES);
    Serial.printf("%s  LTPK: ",(*it).admin?"   (admin)":" (regular)");
    hexPrintRow((*it).LTPK,crypto_sign_PUBLICKEYBYTES);
    Serial.printf("\n");    
  }
}

//////////////////////////////////////

void HAPClient::saveControllers(){

  if(controllerList.empty()){
    nvs_erase_key(hapNVS,"CONTROLLERS");
    return;
  }

  TempBuffer<Controller> tBuf(controllerList.size());                    // create temporary buffer to hold Controller data
  std::copy(controllerList.begin(),controllerList.end(),tBuf.get());      // copy data from linked list to buffer
  
  nvs_set_blob(hapNVS,"CONTROLLERS",tBuf,tBuf.len());      // update data
  nvs_commit(hapNVS);                                            // commit to NVS  
}


//////////////////////////////////////
//////////////////////////////////////

Nonce::Nonce(){
  zero();
}

//////////////////////////////////////

void Nonce::zero(){
  memset(x,0,12);
}

//////////////////////////////////////

uint8_t *Nonce::get(){
  return(x);
}

//////////////////////////////////////

void Nonce::inc(){
  x[4]++;
  if(x[4]==0)
    x[5]++;
}

//////////////////////////////////////
//////////////////////////////////////

HapOut::HapStreamBuffer::HapStreamBuffer(){

  // note - must require all memory allocation to be pulled from INTERNAL heap only

  const uint32_t caps=MALLOC_CAP_DEFAULT | MALLOC_CAP_INTERNAL;

  buffer=(char *)heap_caps_malloc(bufSize+1,caps);                                          // add 1 for adding null terminator when printing text
  encBuf=(uint8_t *)heap_caps_malloc(bufSize+18,caps);                                      // 2-byte AAD + encrypted data + 16-byte authentication tag 
  hash=(uint8_t *)heap_caps_malloc(48,caps);                                                // space for SHA-384 hash output
  ctx = (mbedtls_sha512_context *)heap_caps_malloc(sizeof(mbedtls_sha512_context),caps);    // space for hash context
  
  mbedtls_sha512_init(ctx);                 // initialize context
  mbedtls_sha512_starts_ret(ctx,1);         // start SHA-384 hash (note second argument=1)
  
  setp(buffer, buffer+bufSize-1);           // assign buffer pointers
}

//////////////////////////////////////

HapOut::HapStreamBuffer::~HapStreamBuffer(){
  
  sync();
  free(buffer);
}

//////////////////////////////////////

void HapOut::HapStreamBuffer::flushBuffer(){
  
  int num=pptr()-pbase();

  byteCount+=num;

  buffer[num]='\0';                               // add null terminator but DO NOT increment num (we don't want terminator considered as part of buffer)

  if(callBack)
    callBack(buffer,callBackUserData);

  if(logLevel<=homeSpan.getLogLevel()){
    if(enablePrettyPrint)                         // if pretty print needed, use formatted method
      printFormatted(buffer,num,2);
    else                                          // if not, just print
    Serial.print(buffer);         
  }
  
  if(hapClient!=NULL){
    if(!hapClient->cPair){                        // if not encrypted 
      hapClient->client.write(buffer,num);        // transmit data buffer
      
    } else {                                      // if encrypted
      
      encBuf[0]=num%256;                          // store number of bytes that encrypts this frame (AAD bytes)
      encBuf[1]=num/256;
      crypto_aead_chacha20poly1305_ietf_encrypt(encBuf+2,NULL,(uint8_t *)buffer,num,encBuf,2,NULL,hapClient->a2cNonce.get(),hapClient->a2cKey);   // encrypt buffer with AAD prepended and authentication tag appended
      
      hapClient->client.write(encBuf,num+18);     // transmit encrypted frame
      hapClient->a2cNonce.inc();                  // increment nonce
    }
    delay(1);
  }

  mbedtls_sha512_update_ret(ctx,(uint8_t *)buffer,num);   // update hash

  pbump(-num);                                            // reset buffer pointers
}

//////////////////////////////////////
        
std::streambuf::int_type HapOut::HapStreamBuffer::overflow(std::streambuf::int_type c){
  
  if(c!=EOF){
    *pptr() = c;
    pbump(1);
  }

  flushBuffer();
  return(c);
}

//////////////////////////////////////

int HapOut::HapStreamBuffer::sync(){

  flushBuffer();
  
  logLevel=255;
  hapClient=NULL;
  enablePrettyPrint=false;
  byteCount=0;
  indent=0;
  
  if(callBack){
    callBack(NULL,callBackUserData);
    callBack=NULL;
    callBackUserData=NULL;
  }

  mbedtls_sha512_finish_ret(ctx,hash);    // finish SHA-384 and store hash
  mbedtls_sha512_starts_ret(ctx,1);       // re-start hash for next time

  return(0);
}

//////////////////////////////////////

void HapOut::HapStreamBuffer::printFormatted(char *buf, size_t nChars, size_t nsp){
  
  for(int i=0;i<nChars;i++){
    switch(buf[i]){
      
      case '{':
      case '[':
        Serial.printf("%c\n",buf[i]);
        indent+=nsp;
        for(int j=0;j<indent;j++)
          Serial.printf(" ");
        break;

      case '}':
      case ']':
        Serial.printf("\n");
        indent-=nsp;
        for(int j=0;j<indent;j++)
          Serial.printf(" ");
        Serial.printf("%c",buf[i]);
        break;

      case ',':
        Serial.printf("%c\n",buf[i]);
        for(int j=0;j<indent;j++)
          Serial.printf(" ");
        break;

      default:
        Serial.printf("%c",buf[i]);           
    }
  }
}

/////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////

// instantiate all static HAP Client structures and data

nvs_handle HAPClient::hapNVS;
nvs_handle HAPClient::srpNVS;
HKDF HAPClient::hkdf;                                   
pairState HAPClient::pairStatus;                        
Accessory HAPClient::accessory;                         
list<Controller, Mallocator<Controller>> HAPClient::controllerList;
SRP6A *HAPClient::srp=NULL;
int HAPClient::conNum;
 
