"""
SPDX-License-Identifier: BSD-2

Copyright 2018, Fraunhofer SIT
All rights reserved.
"""

from ._libesys import ffi,lib
from cffi import FFI

### internal ###

def _chkrc(rc):
    if rc != 0:
        raise Exception(rc >> 16, rc & 0xffff)

#### Utilities ####

def TPM2B_unpack(x):
    return ffi.unpack(x.buffer, x.size)

def TPM2B_pack(x, t='DIGEST'):
    if t.startswith("TPM2B_"):
        t = t[6:]
    r = ffi.new("TPM2B_{0} *".format(t))
    r.size = len(x)
    for i in range(r.size):
        r.buffer[i] = x[i]
    return r

#### ESYS_TR classes ####

class EsysTr:
    def __init__(self, ctx, handle):
        self.ctx = ctx
        self.handle = handle
        if ctx:
            self.active = True
        else:
            self.active = False

    def __del__(self):
        if self.active:
            lib.Esys_FlushContext(self.ctx.ctx, self.handle)
        super().__del__(self)

    def setAuth(self, auth):
        if type(auth) is str:
            x = bytearray()
            x.extend(map(ord,auth))
            auth = x
        if str(auth) is not "<cdata 'TPM2B_DIGEST *' owning 66 bytes>":
            auth = TPM2B_pack(auth, 'AUTH')
        _chkrc(lib.Esys_TR_SetAuth(self.ctx.ctx, self.handle, auth))

class EsysTrSess(EsysTr):
    def __init__(ctx, handle):
        super().__init__(self, ctx, handle)
        lib.Esys_TRSess_SetAttributes(self.ctx.ctx,
            lib.TPMA_SESSION_CONTINUESESSION,
            lib.TPMA_SESSION_CONTINUESESSION)

#### All EsysContext functions ####

class EsysContext:
    def __init__(self, tcti=None):
        if tcti is not None:
            raise Exception('pytpm2tss', 'tcti not supported')

        self.ctx_p = ffi.new('ESYS_CONTEXT **')
        _chkrc(lib.Esys_Initialize(self.ctx_p, ffi.NULL, ffi.NULL))
        self.ctx = self.ctx_p[0]
        self.tr = ESYS_TR(self)

    def __del__(self):
        lib.Esys_Finalize(self.ctx_p)

    def Startup(self, startupType):
        _chkrc(lib.Esys_Startup(self.ctx,
         startupType))

    def Shutdown(self, shutdownType,
        session1=None, session2=None, session3=None):
        session1 = session1.handle if session1 else lib.ESYS_TR_NONE
        session2 = session2.handle if session2 else lib.ESYS_TR_NONE
        session3 = session3.handle if session3 else lib.ESYS_TR_NONE
        _chkrc(lib.Esys_Shutdown(self.ctx,
                                  session1, session2, session3,
                                  shutdownType))

    def SelfTest(self, fullTest,
                 session1=None, session2=None, session3=None):
        session1 = session1.handle if session1 else lib.ESYS_TR_NONE
        session2 = session2.handle if session2 else lib.ESYS_TR_NONE
        session3 = session3.handle if session3 else lib.ESYS_TR_NONE
        _chkrc(lib.Esys_SelfTest(self.ctx,
                                  session1, session2, session3,
                                  fullTest))

    def IncrementalSelfTest(self, toTest,
                            session1=None, session2=None, session3=None):
        session1 = session1.handle if session1 else lib.ESYS_TR_NONE
        session2 = session2.handle if session2 else lib.ESYS_TR_NONE
        session3 = session3.handle if session3 else lib.ESYS_TR_NONE
        toDoList = ffi.new('TPML_ALG **')
        _chkrc(lib.Esys_IncrementalSelfTest(self.ctx,
                                             session1, session2, session3,
                                             toTest,
                                             toDoList))
        return(toDoList[0])

    def GetTestResult(self,
                      session1=None, session2=None, session3=None):
        session1 = session1.handle if session1 else lib.ESYS_TR_NONE
        session2 = session2.handle if session2 else lib.ESYS_TR_NONE
        session3 = session3.handle if session3 else lib.ESYS_TR_NONE
        outData = ffi.new('TPM2B_MAX_BUFFER **')
        testResult = ffi.new('TPM2_RC *')
        _chkrc(lib.Esys_GetTestResult(self.ctx,
                                       session1, session2, session3,
                                       outData,
                                       testResult))
        return(outData[0], testResult[0])

    def StartAuthSession(self, tpmKey, bind, 
                         nonceCaller, sessionType, symmetric, authHash,
                         session1=None, session2=None, session3=None):
        session1 = session1.handle if session1 else lib.ESYS_TR_NONE
        session2 = session2.handle if session2 else lib.ESYS_TR_NONE
        session3 = session3.handle if session3 else lib.ESYS_TR_NONE
        sessionHandle = ffi.new('ESYS_TR *')
        _chkrc(lib.Esys_StartAuthSession(self.ctx,
                                          tpmKey.handle,
                                          bind.handle,
                                          session1, session2, session3,
                                          nonceCaller,
                                          sessionType,
                                          symmetric,
                                          authHash,
                                          sessionHandle)) 
        sessionHandleObject = EsysTr(self, sessionHandle[0])
        return(sessionHandleObject)

    def PolicyRestart(self,sessionHandle,
                      session1=None, session2=None, session3=None):
        session1 = session1.handle if session1 else lib.ESYS_TR_NONE
        session2 = session2.handle if session2 else lib.ESYS_TR_NONE
        session3 = session3.handle if session3 else lib.ESYS_TR_NONE
        _chkrc(lib.Esys_PolicyRestart(self.ctx,
                                       sessionHandle.handle,
                                       session1, session2, session3))

    def Create(self,parentHandle, inSensitive, inPublic, outsideInfo, creationPCR,
               session1=None, session2=None, session3=None):
        session1 = session1.handle if session1 else lib.ESYS_TR_NONE
        session2 = session2.handle if session2 else lib.ESYS_TR_NONE
        session3 = session3.handle if session3 else lib.ESYS_TR_NONE
        outPrivate = ffi.new('TPM2B_PRIVATE **')
        outPublic = ffi.new('TPM2B_PUBLIC **')
        creationData = ffi.new('TPM2B_CREATION_DATA **')
        creationHash = ffi.new('TPM2B_DIGEST **')
        creationTicket = ffi.new('TPMT_TK_CREATION **')
        _chkrc(lib.Esys_Create(self.ctx,
                                parentHandle.handle,
                                session1, session2, session3,
                                inSensitive,
                                inPublic,
                                outsideInfo,
                                creationPCR,
                                outPrivate,
                                outPublic,
                                creationData,
                                creationHash,
                                creationTicket))
        return(outPrivate[0], outPublic[0], creationData[0], creationHash[0], creationTicket[0])

    def Load(self,parentHandle, inPrivate, inPublic,
             session1=None, session2=None, session3=None):
        session1 = session1.handle if session1 else lib.ESYS_TR_NONE
        session2 = session2.handle if session2 else lib.ESYS_TR_NONE
        session3 = session3.handle if session3 else lib.ESYS_TR_NONE
        objectHandle = ffi.new('ESYS_TR *')
        _chkrc(lib.Esys_Load(self.ctx,
                              parentHandle.handle,
                              session1, session2, session3,
                              inPrivate,
                              inPublic,
                              objectHandle)) 
        objectHandleObject = EsysTr(self, objectHandle[0])
        return(objectHandleObject)

    def LoadExternal(self, inPrivate, inPublic, hierarchy,
                     session1=None, session2=None, session3=None):
        session1 = session1.handle if session1 else lib.ESYS_TR_NONE
        session2 = session2.handle if session2 else lib.ESYS_TR_NONE
        session3 = session3.handle if session3 else lib.ESYS_TR_NONE
        objectHandle = ffi.new('ESYS_TR *')
        _chkrc(lib.Esys_LoadExternal(self.ctx,
                                      session1, session2, session3,
                                      inPrivate,
                                      inPublic,
                                      hierarchy,
                                      objectHandle)) 
        objectHandleObject = EsysTr(self, objectHandle[0])
        return(objectHandleObject)

    def ReadPublic(self,objectHandle,
                   session1=None, session2=None, session3=None):
        session1 = session1.handle if session1 else lib.ESYS_TR_NONE
        session2 = session2.handle if session2 else lib.ESYS_TR_NONE
        session3 = session3.handle if session3 else lib.ESYS_TR_NONE
        outPublic = ffi.new('TPM2B_PUBLIC **')
        name = ffi.new('TPM2B_NAME **')
        qualifiedName = ffi.new('TPM2B_NAME **')
        _chkrc(lib.Esys_ReadPublic(self.ctx,
                                    objectHandle.handle,
                                    session1, session2, session3,
                                    outPublic,
                                    name,
                                    qualifiedName))
        return(outPublic[0], name[0], qualifiedName[0])

    def ActivateCredential(self,activateHandle,keyHandle, credentialBlob, secret,
                           session1=None, session2=None, session3=None):
        session1 = session1.handle if session1 else lib.ESYS_TR_NONE
        session2 = session2.handle if session2 else lib.ESYS_TR_NONE
        session3 = session3.handle if session3 else lib.ESYS_TR_NONE
        certInfo = ffi.new('TPM2B_DIGEST **')
        _chkrc(lib.Esys_ActivateCredential(self.ctx,
                                            activateHandle.handle,
                                            keyHandle.handle,
                                            session1, session2, session3,
                                            credentialBlob,
                                            secret,
                                            certInfo))
        return(certInfo[0])

    def MakeCredential(self,handle, credential, objectName,
                       session1=None, session2=None, session3=None):
        session1 = session1.handle if session1 else lib.ESYS_TR_NONE
        session2 = session2.handle if session2 else lib.ESYS_TR_NONE
        session3 = session3.handle if session3 else lib.ESYS_TR_NONE
        credentialBlob = ffi.new('TPM2B_ID_OBJECT **')
        secret = ffi.new('TPM2B_ENCRYPTED_SECRET **')
        _chkrc(lib.Esys_MakeCredential(self.ctx,
                                        handle.handle,
                                        session1, session2, session3,
                                        credential,
                                        objectName,
                                        credentialBlob,
                                        secret))
        return(credentialBlob[0], secret[0])

    def Unseal(self,itemHandle,
               session1=None, session2=None, session3=None):
        session1 = session1.handle if session1 else lib.ESYS_TR_NONE
        session2 = session2.handle if session2 else lib.ESYS_TR_NONE
        session3 = session3.handle if session3 else lib.ESYS_TR_NONE
        outData = ffi.new('TPM2B_SENSITIVE_DATA **')
        _chkrc(lib.Esys_Unseal(self.ctx,
                                itemHandle.handle,
                                session1, session2, session3,
                                outData))
        return(outData[0])

    def ObjectChangeAuth(self,objectHandle,parentHandle, newAuth,
                         session1=None, session2=None, session3=None):
        session1 = session1.handle if session1 else lib.ESYS_TR_NONE
        session2 = session2.handle if session2 else lib.ESYS_TR_NONE
        session3 = session3.handle if session3 else lib.ESYS_TR_NONE
        outPrivate = ffi.new('TPM2B_PRIVATE **')
        _chkrc(lib.Esys_ObjectChangeAuth(self.ctx,
                                          objectHandle.handle,
                                          parentHandle.handle,
                                          session1, session2, session3,
                                          newAuth,
                                          outPrivate))
        return(outPrivate[0])

    def CreateLoaded(self,parentHandle, inSensitive, inPublic,
                     session1=None, session2=None, session3=None):
        session1 = session1.handle if session1 else lib.ESYS_TR_NONE
        session2 = session2.handle if session2 else lib.ESYS_TR_NONE
        session3 = session3.handle if session3 else lib.ESYS_TR_NONE
        objectHandle = ffi.new('ESYS_TR *')
        outPrivate = ffi.new('TPM2B_PRIVATE **')
        outPublic = ffi.new('TPM2B_PUBLIC **')
        _chkrc(lib.Esys_CreateLoaded(self.ctx,
                                      parentHandle.handle,
                                      session1, session2, session3,
                                      inSensitive,
                                      inPublic,
                                      objectHandle,
                                      outPrivate,
                                      outPublic)) 
        objectHandleObject = EsysTr(self, objectHandle[0])
        return(objectHandleObject, outPrivate[0], outPublic[0])

    def Duplicate(self,objectHandle,newParentHandle, encryptionKeyIn, symmetricAlg,
                  session1=None, session2=None, session3=None):
        session1 = session1.handle if session1 else lib.ESYS_TR_NONE
        session2 = session2.handle if session2 else lib.ESYS_TR_NONE
        session3 = session3.handle if session3 else lib.ESYS_TR_NONE
        encryptionKeyOut = ffi.new('TPM2B_DATA **')
        duplicate = ffi.new('TPM2B_PRIVATE **')
        outSymSeed = ffi.new('TPM2B_ENCRYPTED_SECRET **')
        _chkrc(lib.Esys_Duplicate(self.ctx,
                                   objectHandle.handle,
                                   newParentHandle.handle,
                                   session1, session2, session3,
                                   encryptionKeyIn,
                                   symmetricAlg,
                                   encryptionKeyOut,
                                   duplicate,
                                   outSymSeed))
        return(encryptionKeyOut[0], duplicate[0], outSymSeed[0])

    def Rewrap(self,oldParent,newParent, inDuplicate, name, inSymSeed,
               session1=None, session2=None, session3=None):
        session1 = session1.handle if session1 else lib.ESYS_TR_NONE
        session2 = session2.handle if session2 else lib.ESYS_TR_NONE
        session3 = session3.handle if session3 else lib.ESYS_TR_NONE
        outDuplicate = ffi.new('TPM2B_PRIVATE **')
        outSymSeed = ffi.new('TPM2B_ENCRYPTED_SECRET **')
        _chkrc(lib.Esys_Rewrap(self.ctx,
                                oldParent.handle,
                                newParent.handle,
                                session1, session2, session3,
                                inDuplicate,
                                name,
                                inSymSeed,
                                outDuplicate,
                                outSymSeed))
        return(outDuplicate[0], outSymSeed[0])

    def Import(self,parentHandle, encryptionKey, objectPublic, duplicate, inSymSeed, symmetricAlg,
               session1=None, session2=None, session3=None):
        session1 = session1.handle if session1 else lib.ESYS_TR_NONE
        session2 = session2.handle if session2 else lib.ESYS_TR_NONE
        session3 = session3.handle if session3 else lib.ESYS_TR_NONE
        outPrivate = ffi.new('TPM2B_PRIVATE **')
        _chkrc(lib.Esys_Import(self.ctx,
                                parentHandle.handle,
                                session1, session2, session3,
                                encryptionKey,
                                objectPublic,
                                duplicate,
                                inSymSeed,
                                symmetricAlg,
                                outPrivate))
        return(outPrivate[0])

    def RSA_Encrypt(self,keyHandle, message, inScheme, label,
                    session1=None, session2=None, session3=None):
        session1 = session1.handle if session1 else lib.ESYS_TR_NONE
        session2 = session2.handle if session2 else lib.ESYS_TR_NONE
        session3 = session3.handle if session3 else lib.ESYS_TR_NONE
        outData = ffi.new('TPM2B_PUBLIC_KEY_RSA **')
        _chkrc(lib.Esys_RSA_Encrypt(self.ctx,
                                     keyHandle.handle,
                                     session1, session2, session3,
                                     message,
                                     inScheme,
                                     label,
                                     outData))
        return(outData[0])

    def RSA_Decrypt(self,keyHandle, cipherText, inScheme, label,
                    session1=None, session2=None, session3=None):
        session1 = session1.handle if session1 else lib.ESYS_TR_NONE
        session2 = session2.handle if session2 else lib.ESYS_TR_NONE
        session3 = session3.handle if session3 else lib.ESYS_TR_NONE
        message = ffi.new('TPM2B_PUBLIC_KEY_RSA **')
        _chkrc(lib.Esys_RSA_Decrypt(self.ctx,
                                     keyHandle.handle,
                                     session1, session2, session3,
                                     cipherText,
                                     inScheme,
                                     label,
                                     message))
        return(message[0])

    def ECDH_KeyGen(self,keyHandle,
                    session1=None, session2=None, session3=None):
        session1 = session1.handle if session1 else lib.ESYS_TR_NONE
        session2 = session2.handle if session2 else lib.ESYS_TR_NONE
        session3 = session3.handle if session3 else lib.ESYS_TR_NONE
        zPoint = ffi.new('TPM2B_ECC_POINT **')
        pubPoint = ffi.new('TPM2B_ECC_POINT **')
        _chkrc(lib.Esys_ECDH_KeyGen(self.ctx,
                                     keyHandle.handle,
                                     session1, session2, session3,
                                     zPoint,
                                     pubPoint))
        return(zPoint[0], pubPoint[0])

    def ECDH_ZGen(self,keyHandle, inPoint,
                  session1=None, session2=None, session3=None):
        session1 = session1.handle if session1 else lib.ESYS_TR_NONE
        session2 = session2.handle if session2 else lib.ESYS_TR_NONE
        session3 = session3.handle if session3 else lib.ESYS_TR_NONE
        outPoint = ffi.new('TPM2B_ECC_POINT **')
        _chkrc(lib.Esys_ECDH_ZGen(self.ctx,
                                   keyHandle.handle,
                                   session1, session2, session3,
                                   inPoint,
                                   outPoint))
        return(outPoint[0])

    def ECC_Parameters(self, curveID,
                       session1=None, session2=None, session3=None):
        session1 = session1.handle if session1 else lib.ESYS_TR_NONE
        session2 = session2.handle if session2 else lib.ESYS_TR_NONE
        session3 = session3.handle if session3 else lib.ESYS_TR_NONE
        parameters = ffi.new('TPMS_ALGORITHM_DETAIL_ECC **')
        _chkrc(lib.Esys_ECC_Parameters(self.ctx,
                                        session1, session2, session3,
                                        curveID,
                                        parameters))
        return(parameters[0])

    def ZGen_2Phase(self,keyA, inQsB, inQeB, inScheme, counter,
                    session1=None, session2=None, session3=None):
        session1 = session1.handle if session1 else lib.ESYS_TR_NONE
        session2 = session2.handle if session2 else lib.ESYS_TR_NONE
        session3 = session3.handle if session3 else lib.ESYS_TR_NONE
        outZ1 = ffi.new('TPM2B_ECC_POINT **')
        outZ2 = ffi.new('TPM2B_ECC_POINT **')
        _chkrc(lib.Esys_ZGen_2Phase(self.ctx,
                                     keyA.handle,
                                     session1, session2, session3,
                                     inQsB,
                                     inQeB,
                                     inScheme,
                                     counter,
                                     outZ1,
                                     outZ2))
        return(outZ1[0], outZ2[0])

    def EncryptDecrypt(self,keyHandle, decrypt, mode, ivIn, inData,
                       session1=None, session2=None, session3=None):
        session1 = session1.handle if session1 else lib.ESYS_TR_NONE
        session2 = session2.handle if session2 else lib.ESYS_TR_NONE
        session3 = session3.handle if session3 else lib.ESYS_TR_NONE
        outData = ffi.new('TPM2B_MAX_BUFFER **')
        ivOut = ffi.new('TPM2B_IV **')
        _chkrc(lib.Esys_EncryptDecrypt(self.ctx,
                                        keyHandle.handle,
                                        session1, session2, session3,
                                        decrypt,
                                        mode,
                                        ivIn,
                                        inData,
                                        outData,
                                        ivOut))
        return(outData[0], ivOut[0])

    def EncryptDecrypt2(self,keyHandle, inData, decrypt, mode, ivIn,
                        session1=None, session2=None, session3=None):
        session1 = session1.handle if session1 else lib.ESYS_TR_NONE
        session2 = session2.handle if session2 else lib.ESYS_TR_NONE
        session3 = session3.handle if session3 else lib.ESYS_TR_NONE
        outData = ffi.new('TPM2B_MAX_BUFFER **')
        ivOut = ffi.new('TPM2B_IV **')
        _chkrc(lib.Esys_EncryptDecrypt2(self.ctx,
                                         keyHandle.handle,
                                         session1, session2, session3,
                                         inData,
                                         decrypt,
                                         mode,
                                         ivIn,
                                         outData,
                                         ivOut))
        return(outData[0], ivOut[0])

    def Hash(self, data, hashAlg, hierarchy,
             session1=None, session2=None, session3=None):
        session1 = session1.handle if session1 else lib.ESYS_TR_NONE
        session2 = session2.handle if session2 else lib.ESYS_TR_NONE
        session3 = session3.handle if session3 else lib.ESYS_TR_NONE
        outHash = ffi.new('TPM2B_DIGEST **')
        validation = ffi.new('TPMT_TK_HASHCHECK **')
        _chkrc(lib.Esys_Hash(self.ctx,
                              session1, session2, session3,
                              data,
                              hashAlg,
                              hierarchy,
                              outHash,
                              validation))
        return(outHash[0], validation[0])

    def HMAC(self,handle, buffer, hashAlg,
             session1=None, session2=None, session3=None):
        session1 = session1.handle if session1 else lib.ESYS_TR_NONE
        session2 = session2.handle if session2 else lib.ESYS_TR_NONE
        session3 = session3.handle if session3 else lib.ESYS_TR_NONE
        outHMAC = ffi.new('TPM2B_DIGEST **')
        _chkrc(lib.Esys_HMAC(self.ctx,
                              handle.handle,
                              session1, session2, session3,
                              buffer,
                              hashAlg,
                              outHMAC))
        return(outHMAC[0])

    def GetRandom(self, bytesRequested,
                  session1=None, session2=None, session3=None):
        session1 = session1.handle if session1 else lib.ESYS_TR_NONE
        session2 = session2.handle if session2 else lib.ESYS_TR_NONE
        session3 = session3.handle if session3 else lib.ESYS_TR_NONE
        randomBytes = ffi.new('TPM2B_DIGEST **')
        _chkrc(lib.Esys_GetRandom(self.ctx,
                                   session1, session2, session3,
                                   bytesRequested,
                                   randomBytes))
        return(randomBytes[0])

    def StirRandom(self, inData,
                   session1=None, session2=None, session3=None):
        session1 = session1.handle if session1 else lib.ESYS_TR_NONE
        session2 = session2.handle if session2 else lib.ESYS_TR_NONE
        session3 = session3.handle if session3 else lib.ESYS_TR_NONE
        _chkrc(lib.Esys_StirRandom(self.ctx,
                                    session1, session2, session3,
                                    inData))

    def HMAC_Start(self,handle, auth, hashAlg,
                   session1=None, session2=None, session3=None):
        session1 = session1.handle if session1 else lib.ESYS_TR_NONE
        session2 = session2.handle if session2 else lib.ESYS_TR_NONE
        session3 = session3.handle if session3 else lib.ESYS_TR_NONE
        sequenceHandle = ffi.new('ESYS_TR *')
        _chkrc(lib.Esys_HMAC_Start(self.ctx,
                                    handle.handle,
                                    session1, session2, session3,
                                    auth,
                                    hashAlg,
                                    sequenceHandle)) 
        sequenceHandleObject = EsysTr(self, sequenceHandle[0])
        return(sequenceHandleObject)

    def HashSequenceStart(self, auth, hashAlg,
                          session1=None, session2=None, session3=None):
        session1 = session1.handle if session1 else lib.ESYS_TR_NONE
        session2 = session2.handle if session2 else lib.ESYS_TR_NONE
        session3 = session3.handle if session3 else lib.ESYS_TR_NONE
        sequenceHandle = ffi.new('ESYS_TR *')
        _chkrc(lib.Esys_HashSequenceStart(self.ctx,
                                           session1, session2, session3,
                                           auth,
                                           hashAlg,
                                           sequenceHandle)) 
        sequenceHandleObject = EsysTr(self, sequenceHandle[0])
        return(sequenceHandleObject)

    def SequenceUpdate(self,sequenceHandle, buffer,
                       session1=None, session2=None, session3=None):
        session1 = session1.handle if session1 else lib.ESYS_TR_NONE
        session2 = session2.handle if session2 else lib.ESYS_TR_NONE
        session3 = session3.handle if session3 else lib.ESYS_TR_NONE
        _chkrc(lib.Esys_SequenceUpdate(self.ctx,
                                        sequenceHandle.handle,
                                        session1, session2, session3,
                                        buffer))

    def SequenceComplete(self,sequenceHandle, buffer, hierarchy,
                         session1=None, session2=None, session3=None):
        session1 = session1.handle if session1 else lib.ESYS_TR_NONE
        session2 = session2.handle if session2 else lib.ESYS_TR_NONE
        session3 = session3.handle if session3 else lib.ESYS_TR_NONE
        result = ffi.new('TPM2B_DIGEST **')
        validation = ffi.new('TPMT_TK_HASHCHECK **')
        _chkrc(lib.Esys_SequenceComplete(self.ctx,
                                          sequenceHandle.handle,
                                          session1, session2, session3,
                                          buffer,
                                          hierarchy,
                                          result,
                                          validation))
        return(result[0], validation[0])

    def EventSequenceComplete(self,pcrHandle,sequenceHandle, buffer,
                              session1=None, session2=None, session3=None):
        session1 = session1.handle if session1 else lib.ESYS_TR_NONE
        session2 = session2.handle if session2 else lib.ESYS_TR_NONE
        session3 = session3.handle if session3 else lib.ESYS_TR_NONE
        results = ffi.new('TPML_DIGEST_VALUES **')
        _chkrc(lib.Esys_EventSequenceComplete(self.ctx,
                                               pcrHandle.handle,
                                               sequenceHandle.handle,
                                               session1, session2, session3,
                                               buffer,
                                               results))
        return(results[0])

    def Certify(self,objectHandle,signHandle, qualifyingData, inScheme,
                session1=None, session2=None, session3=None):
        session1 = session1.handle if session1 else lib.ESYS_TR_NONE
        session2 = session2.handle if session2 else lib.ESYS_TR_NONE
        session3 = session3.handle if session3 else lib.ESYS_TR_NONE
        certifyInfo = ffi.new('TPM2B_ATTEST **')
        signature = ffi.new('TPMT_SIGNATURE **')
        _chkrc(lib.Esys_Certify(self.ctx,
                                 objectHandle.handle,
                                 signHandle.handle,
                                 session1, session2, session3,
                                 qualifyingData,
                                 inScheme,
                                 certifyInfo,
                                 signature))
        return(certifyInfo[0], signature[0])

    def CertifyCreation(self,signHandle,objectHandle, qualifyingData, creationHash, inScheme, creationTicket,
                        session1=None, session2=None, session3=None):
        session1 = session1.handle if session1 else lib.ESYS_TR_NONE
        session2 = session2.handle if session2 else lib.ESYS_TR_NONE
        session3 = session3.handle if session3 else lib.ESYS_TR_NONE
        certifyInfo = ffi.new('TPM2B_ATTEST **')
        signature = ffi.new('TPMT_SIGNATURE **')
        _chkrc(lib.Esys_CertifyCreation(self.ctx,
                                         signHandle.handle,
                                         objectHandle.handle,
                                         session1, session2, session3,
                                         qualifyingData,
                                         creationHash,
                                         inScheme,
                                         creationTicket,
                                         certifyInfo,
                                         signature))
        return(certifyInfo[0], signature[0])

    def Quote(self,signHandle, qualifyingData, inScheme, PCRselect,
              session1=None, session2=None, session3=None):
        session1 = session1.handle if session1 else lib.ESYS_TR_NONE
        session2 = session2.handle if session2 else lib.ESYS_TR_NONE
        session3 = session3.handle if session3 else lib.ESYS_TR_NONE
        quoted = ffi.new('TPM2B_ATTEST **')
        signature = ffi.new('TPMT_SIGNATURE **')
        _chkrc(lib.Esys_Quote(self.ctx,
                               signHandle.handle,
                               session1, session2, session3,
                               qualifyingData,
                               inScheme,
                               PCRselect,
                               quoted,
                               signature))
        return(quoted[0], signature[0])

    def GetSessionAuditDigest(self,privacyAdminHandle,signHandle,sessionHandle, qualifyingData, inScheme,
                              session1=None, session2=None, session3=None):
        session1 = session1.handle if session1 else lib.ESYS_TR_NONE
        session2 = session2.handle if session2 else lib.ESYS_TR_NONE
        session3 = session3.handle if session3 else lib.ESYS_TR_NONE
        auditInfo = ffi.new('TPM2B_ATTEST **')
        signature = ffi.new('TPMT_SIGNATURE **')
        _chkrc(lib.Esys_GetSessionAuditDigest(self.ctx,
                                               privacyAdminHandle.handle,
                                               signHandle.handle,
                                               sessionHandle.handle,
                                               session1, session2, session3,
                                               qualifyingData,
                                               inScheme,
                                               auditInfo,
                                               signature))
        return(auditInfo[0], signature[0])

    def GetCommandAuditDigest(self,privacyHandle,signHandle, qualifyingData, inScheme,
                              session1=None, session2=None, session3=None):
        session1 = session1.handle if session1 else lib.ESYS_TR_NONE
        session2 = session2.handle if session2 else lib.ESYS_TR_NONE
        session3 = session3.handle if session3 else lib.ESYS_TR_NONE
        auditInfo = ffi.new('TPM2B_ATTEST **')
        signature = ffi.new('TPMT_SIGNATURE **')
        _chkrc(lib.Esys_GetCommandAuditDigest(self.ctx,
                                               privacyHandle.handle,
                                               signHandle.handle,
                                               session1, session2, session3,
                                               qualifyingData,
                                               inScheme,
                                               auditInfo,
                                               signature))
        return(auditInfo[0], signature[0])

    def GetTime(self,privacyAdminHandle,signHandle, qualifyingData, inScheme,
                session1=None, session2=None, session3=None):
        session1 = session1.handle if session1 else lib.ESYS_TR_NONE
        session2 = session2.handle if session2 else lib.ESYS_TR_NONE
        session3 = session3.handle if session3 else lib.ESYS_TR_NONE
        timeInfo = ffi.new('TPM2B_ATTEST **')
        signature = ffi.new('TPMT_SIGNATURE **')
        _chkrc(lib.Esys_GetTime(self.ctx,
                                 privacyAdminHandle.handle,
                                 signHandle.handle,
                                 session1, session2, session3,
                                 qualifyingData,
                                 inScheme,
                                 timeInfo,
                                 signature))
        return(timeInfo[0], signature[0])

    def Commit(self,signHandle, P1, s2, y2,
               session1=None, session2=None, session3=None):
        session1 = session1.handle if session1 else lib.ESYS_TR_NONE
        session2 = session2.handle if session2 else lib.ESYS_TR_NONE
        session3 = session3.handle if session3 else lib.ESYS_TR_NONE
        K = ffi.new('TPM2B_ECC_POINT **')
        L = ffi.new('TPM2B_ECC_POINT **')
        E = ffi.new('TPM2B_ECC_POINT **')
        counter = ffi.new('UINT16 *')
        _chkrc(lib.Esys_Commit(self.ctx,
                                signHandle.handle,
                                session1, session2, session3,
                                P1,
                                s2,
                                y2,
                                K,
                                L,
                                E,
                                counter))
        return(K[0], L[0], E[0], counter[0])

    def EC_Ephemeral(self, curveID,
                     session1=None, session2=None, session3=None):
        session1 = session1.handle if session1 else lib.ESYS_TR_NONE
        session2 = session2.handle if session2 else lib.ESYS_TR_NONE
        session3 = session3.handle if session3 else lib.ESYS_TR_NONE
        Q = ffi.new('TPM2B_ECC_POINT **')
        counter = ffi.new('UINT16 *')
        _chkrc(lib.Esys_EC_Ephemeral(self.ctx,
                                      session1, session2, session3,
                                      curveID,
                                      Q,
                                      counter))
        return(Q[0], counter[0])

    def VerifySignature(self,keyHandle, digest, signature,
                        session1=None, session2=None, session3=None):
        session1 = session1.handle if session1 else lib.ESYS_TR_NONE
        session2 = session2.handle if session2 else lib.ESYS_TR_NONE
        session3 = session3.handle if session3 else lib.ESYS_TR_NONE
        validation = ffi.new('TPMT_TK_VERIFIED **')
        _chkrc(lib.Esys_VerifySignature(self.ctx,
                                         keyHandle.handle,
                                         session1, session2, session3,
                                         digest,
                                         signature,
                                         validation))
        return(validation[0])

    def Sign(self,keyHandle, digest, inScheme, validation,
             session1=None, session2=None, session3=None):
        session1 = session1.handle if session1 else lib.ESYS_TR_NONE
        session2 = session2.handle if session2 else lib.ESYS_TR_NONE
        session3 = session3.handle if session3 else lib.ESYS_TR_NONE
        signature = ffi.new('TPMT_SIGNATURE **')
        _chkrc(lib.Esys_Sign(self.ctx,
                              keyHandle.handle,
                              session1, session2, session3,
                              digest,
                              inScheme,
                              validation,
                              signature))
        return(signature[0])

    def SetCommandCodeAuditStatus(self,auth, auditAlg, setList, clearList,
                                  session1=None, session2=None, session3=None):
        session1 = session1.handle if session1 else lib.ESYS_TR_NONE
        session2 = session2.handle if session2 else lib.ESYS_TR_NONE
        session3 = session3.handle if session3 else lib.ESYS_TR_NONE
        _chkrc(lib.Esys_SetCommandCodeAuditStatus(self.ctx,
                                                   auth.handle,
                                                   session1, session2, session3,
                                                   auditAlg,
                                                   setList,
                                                   clearList))

    def PCR_Extend(self,pcrHandle, digests,
                   session1=None, session2=None, session3=None):
        session1 = session1.handle if session1 else lib.ESYS_TR_NONE
        session2 = session2.handle if session2 else lib.ESYS_TR_NONE
        session3 = session3.handle if session3 else lib.ESYS_TR_NONE
        _chkrc(lib.Esys_PCR_Extend(self.ctx,
                                    pcrHandle.handle,
                                    session1, session2, session3,
                                    digests))

    def PCR_Event(self,pcrHandle, eventData,
                  session1=None, session2=None, session3=None):
        session1 = session1.handle if session1 else lib.ESYS_TR_NONE
        session2 = session2.handle if session2 else lib.ESYS_TR_NONE
        session3 = session3.handle if session3 else lib.ESYS_TR_NONE
        digests = ffi.new('TPML_DIGEST_VALUES **')
        _chkrc(lib.Esys_PCR_Event(self.ctx,
                                   pcrHandle.handle,
                                   session1, session2, session3,
                                   eventData,
                                   digests))
        return(digests[0])

    def PCR_Read(self, pcrSelectionIn,
                 session1=None, session2=None, session3=None):
        session1 = session1.handle if session1 else lib.ESYS_TR_NONE
        session2 = session2.handle if session2 else lib.ESYS_TR_NONE
        session3 = session3.handle if session3 else lib.ESYS_TR_NONE
        pcrUpdateCounter = ffi.new('UINT32 *')
        pcrSelectionOut = ffi.new('TPML_PCR_SELECTION **')
        pcrValues = ffi.new('TPML_DIGEST **')
        _chkrc(lib.Esys_PCR_Read(self.ctx,
                                  session1, session2, session3,
                                  pcrSelectionIn,
                                  pcrUpdateCounter,
                                  pcrSelectionOut,
                                  pcrValues))
        return(pcrUpdateCounter[0], pcrSelectionOut[0], pcrValues[0])

    def PCR_Allocate(self,authHandle, pcrAllocation,
                     session1=None, session2=None, session3=None):
        session1 = session1.handle if session1 else lib.ESYS_TR_NONE
        session2 = session2.handle if session2 else lib.ESYS_TR_NONE
        session3 = session3.handle if session3 else lib.ESYS_TR_NONE
        allocationSuccess = ffi.new('TPMI_YES_NO *')
        maxPCR = ffi.new('UINT32 *')
        sizeNeeded = ffi.new('UINT32 *')
        sizeAvailable = ffi.new('UINT32 *')
        _chkrc(lib.Esys_PCR_Allocate(self.ctx,
                                      authHandle.handle,
                                      session1, session2, session3,
                                      pcrAllocation,
                                      allocationSuccess,
                                      maxPCR,
                                      sizeNeeded,
                                      sizeAvailable))
        return(allocationSuccess[0], maxPCR[0], sizeNeeded[0], sizeAvailable[0])

    def PCR_SetAuthPolicy(self,authHandle, authPolicy, hashAlg, pcrNum,
                          session1=None, session2=None, session3=None):
        session1 = session1.handle if session1 else lib.ESYS_TR_NONE
        session2 = session2.handle if session2 else lib.ESYS_TR_NONE
        session3 = session3.handle if session3 else lib.ESYS_TR_NONE
        _chkrc(lib.Esys_PCR_SetAuthPolicy(self.ctx,
                                           authHandle.handle,
                                           session1, session2, session3,
                                           authPolicy,
                                           hashAlg,
                                           pcrNum))

    def PCR_SetAuthValue(self,pcrHandle, auth,
                         session1=None, session2=None, session3=None):
        session1 = session1.handle if session1 else lib.ESYS_TR_NONE
        session2 = session2.handle if session2 else lib.ESYS_TR_NONE
        session3 = session3.handle if session3 else lib.ESYS_TR_NONE
        _chkrc(lib.Esys_PCR_SetAuthValue(self.ctx,
                                          pcrHandle.handle,
                                          session1, session2, session3,
                                          auth))

    def PCR_Reset(self,pcrHandle,
                  session1=None, session2=None, session3=None):
        session1 = session1.handle if session1 else lib.ESYS_TR_NONE
        session2 = session2.handle if session2 else lib.ESYS_TR_NONE
        session3 = session3.handle if session3 else lib.ESYS_TR_NONE
        _chkrc(lib.Esys_PCR_Reset(self.ctx,
                                   pcrHandle.handle,
                                   session1, session2, session3))

    def PolicySigned(self,authObject,policySession, nonceTPM, cpHashA, policyRef, expiration, auth,
                     session1=None, session2=None, session3=None):
        session1 = session1.handle if session1 else lib.ESYS_TR_NONE
        session2 = session2.handle if session2 else lib.ESYS_TR_NONE
        session3 = session3.handle if session3 else lib.ESYS_TR_NONE
        timeout = ffi.new('TPM2B_TIMEOUT **')
        policyTicket = ffi.new('TPMT_TK_AUTH **')
        _chkrc(lib.Esys_PolicySigned(self.ctx,
                                      authObject.handle,
                                      policySession.handle,
                                      session1, session2, session3,
                                      nonceTPM,
                                      cpHashA,
                                      policyRef,
                                      expiration,
                                      auth,
                                      timeout,
                                      policyTicket))
        return(timeout[0], policyTicket[0])

    def PolicySecret(self,authHandle,policySession, nonceTPM, cpHashA, policyRef, expiration,
                     session1=None, session2=None, session3=None):
        session1 = session1.handle if session1 else lib.ESYS_TR_NONE
        session2 = session2.handle if session2 else lib.ESYS_TR_NONE
        session3 = session3.handle if session3 else lib.ESYS_TR_NONE
        timeout = ffi.new('TPM2B_TIMEOUT **')
        policyTicket = ffi.new('TPMT_TK_AUTH **')
        _chkrc(lib.Esys_PolicySecret(self.ctx,
                                      authHandle.handle,
                                      policySession.handle,
                                      session1, session2, session3,
                                      nonceTPM,
                                      cpHashA,
                                      policyRef,
                                      expiration,
                                      timeout,
                                      policyTicket))
        return(timeout[0], policyTicket[0])

    def PolicyTicket(self,policySession, timeout, cpHashA, policyRef, authName, ticket,
                     session1=None, session2=None, session3=None):
        session1 = session1.handle if session1 else lib.ESYS_TR_NONE
        session2 = session2.handle if session2 else lib.ESYS_TR_NONE
        session3 = session3.handle if session3 else lib.ESYS_TR_NONE
        _chkrc(lib.Esys_PolicyTicket(self.ctx,
                                      policySession.handle,
                                      session1, session2, session3,
                                      timeout,
                                      cpHashA,
                                      policyRef,
                                      authName,
                                      ticket))

    def PolicyOR(self,policySession, pHashList,
                 session1=None, session2=None, session3=None):
        session1 = session1.handle if session1 else lib.ESYS_TR_NONE
        session2 = session2.handle if session2 else lib.ESYS_TR_NONE
        session3 = session3.handle if session3 else lib.ESYS_TR_NONE
        _chkrc(lib.Esys_PolicyOR(self.ctx,
                                  policySession.handle,
                                  session1, session2, session3,
                                  pHashList))

    def PolicyPCR(self,policySession, pcrDigest, pcrs,
                  session1=None, session2=None, session3=None):
        session1 = session1.handle if session1 else lib.ESYS_TR_NONE
        session2 = session2.handle if session2 else lib.ESYS_TR_NONE
        session3 = session3.handle if session3 else lib.ESYS_TR_NONE
        _chkrc(lib.Esys_PolicyPCR(self.ctx,
                                   policySession.handle,
                                   session1, session2, session3,
                                   pcrDigest,
                                   pcrs))

    def PolicyLocality(self,policySession, locality,
                       session1=None, session2=None, session3=None):
        session1 = session1.handle if session1 else lib.ESYS_TR_NONE
        session2 = session2.handle if session2 else lib.ESYS_TR_NONE
        session3 = session3.handle if session3 else lib.ESYS_TR_NONE
        _chkrc(lib.Esys_PolicyLocality(self.ctx,
                                        policySession.handle,
                                        session1, session2, session3,
                                        locality))

    def PolicyNV(self,authHandle,nvIndex,policySession, operandB, offset, operation,
                 session1=None, session2=None, session3=None):
        session1 = session1.handle if session1 else lib.ESYS_TR_NONE
        session2 = session2.handle if session2 else lib.ESYS_TR_NONE
        session3 = session3.handle if session3 else lib.ESYS_TR_NONE
        _chkrc(lib.Esys_PolicyNV(self.ctx,
                                  authHandle.handle,
                                  nvIndex.handle,
                                  policySession.handle,
                                  session1, session2, session3,
                                  operandB,
                                  offset,
                                  operation))

    def PolicyCounterTimer(self,policySession, operandB, offset, operation,
                           session1=None, session2=None, session3=None):
        session1 = session1.handle if session1 else lib.ESYS_TR_NONE
        session2 = session2.handle if session2 else lib.ESYS_TR_NONE
        session3 = session3.handle if session3 else lib.ESYS_TR_NONE
        _chkrc(lib.Esys_PolicyCounterTimer(self.ctx,
                                            policySession.handle,
                                            session1, session2, session3,
                                            operandB,
                                            offset,
                                            operation))

    def PolicyCommandCode(self,policySession, code,
                          session1=None, session2=None, session3=None):
        session1 = session1.handle if session1 else lib.ESYS_TR_NONE
        session2 = session2.handle if session2 else lib.ESYS_TR_NONE
        session3 = session3.handle if session3 else lib.ESYS_TR_NONE
        _chkrc(lib.Esys_PolicyCommandCode(self.ctx,
                                           policySession.handle,
                                           session1, session2, session3,
                                           code))

    def PolicyPhysicalPresence(self,policySession,
                               session1=None, session2=None, session3=None):
        session1 = session1.handle if session1 else lib.ESYS_TR_NONE
        session2 = session2.handle if session2 else lib.ESYS_TR_NONE
        session3 = session3.handle if session3 else lib.ESYS_TR_NONE
        _chkrc(lib.Esys_PolicyPhysicalPresence(self.ctx,
                                                policySession.handle,
                                                session1, session2, session3))

    def PolicyCpHash(self,policySession, cpHashA,
                     session1=None, session2=None, session3=None):
        session1 = session1.handle if session1 else lib.ESYS_TR_NONE
        session2 = session2.handle if session2 else lib.ESYS_TR_NONE
        session3 = session3.handle if session3 else lib.ESYS_TR_NONE
        _chkrc(lib.Esys_PolicyCpHash(self.ctx,
                                      policySession.handle,
                                      session1, session2, session3,
                                      cpHashA))

    def PolicyNameHash(self,policySession, nameHash,
                       session1=None, session2=None, session3=None):
        session1 = session1.handle if session1 else lib.ESYS_TR_NONE
        session2 = session2.handle if session2 else lib.ESYS_TR_NONE
        session3 = session3.handle if session3 else lib.ESYS_TR_NONE
        _chkrc(lib.Esys_PolicyNameHash(self.ctx,
                                        policySession.handle,
                                        session1, session2, session3,
                                        nameHash))

    def PolicyDuplicationSelect(self,policySession, objectName, newParentName, includeObject,
                                session1=None, session2=None, session3=None):
        session1 = session1.handle if session1 else lib.ESYS_TR_NONE
        session2 = session2.handle if session2 else lib.ESYS_TR_NONE
        session3 = session3.handle if session3 else lib.ESYS_TR_NONE
        _chkrc(lib.Esys_PolicyDuplicationSelect(self.ctx,
                                                 policySession.handle,
                                                 session1, session2, session3,
                                                 objectName,
                                                 newParentName,
                                                 includeObject))

    def PolicyAuthorize(self,policySession, approvedPolicy, policyRef, keySign, checkTicket,
                        session1=None, session2=None, session3=None):
        session1 = session1.handle if session1 else lib.ESYS_TR_NONE
        session2 = session2.handle if session2 else lib.ESYS_TR_NONE
        session3 = session3.handle if session3 else lib.ESYS_TR_NONE
        _chkrc(lib.Esys_PolicyAuthorize(self.ctx,
                                         policySession.handle,
                                         session1, session2, session3,
                                         approvedPolicy,
                                         policyRef,
                                         keySign,
                                         checkTicket))

    def PolicyAuthValue(self,policySession,
                        session1=None, session2=None, session3=None):
        session1 = session1.handle if session1 else lib.ESYS_TR_NONE
        session2 = session2.handle if session2 else lib.ESYS_TR_NONE
        session3 = session3.handle if session3 else lib.ESYS_TR_NONE
        _chkrc(lib.Esys_PolicyAuthValue(self.ctx,
                                         policySession.handle,
                                         session1, session2, session3))

    def PolicyPassword(self,policySession,
                       session1=None, session2=None, session3=None):
        session1 = session1.handle if session1 else lib.ESYS_TR_NONE
        session2 = session2.handle if session2 else lib.ESYS_TR_NONE
        session3 = session3.handle if session3 else lib.ESYS_TR_NONE
        _chkrc(lib.Esys_PolicyPassword(self.ctx,
                                        policySession.handle,
                                        session1, session2, session3))

    def PolicyGetDigest(self,policySession,
                        session1=None, session2=None, session3=None):
        session1 = session1.handle if session1 else lib.ESYS_TR_NONE
        session2 = session2.handle if session2 else lib.ESYS_TR_NONE
        session3 = session3.handle if session3 else lib.ESYS_TR_NONE
        policyDigest = ffi.new('TPM2B_DIGEST **')
        _chkrc(lib.Esys_PolicyGetDigest(self.ctx,
                                         policySession.handle,
                                         session1, session2, session3,
                                         policyDigest))
        return(policyDigest[0])

    def PolicyNvWritten(self,policySession, writtenSet,
                        session1=None, session2=None, session3=None):
        session1 = session1.handle if session1 else lib.ESYS_TR_NONE
        session2 = session2.handle if session2 else lib.ESYS_TR_NONE
        session3 = session3.handle if session3 else lib.ESYS_TR_NONE
        _chkrc(lib.Esys_PolicyNvWritten(self.ctx,
                                         policySession.handle,
                                         session1, session2, session3,
                                         writtenSet))

    def PolicyTemplate(self,policySession, templateHash,
                       session1=None, session2=None, session3=None):
        session1 = session1.handle if session1 else lib.ESYS_TR_NONE
        session2 = session2.handle if session2 else lib.ESYS_TR_NONE
        session3 = session3.handle if session3 else lib.ESYS_TR_NONE
        _chkrc(lib.Esys_PolicyTemplate(self.ctx,
                                        policySession.handle,
                                        session1, session2, session3,
                                        templateHash))

    def PolicyAuthorizeNV(self,authHandle,nvIndex,policySession,
                          session1=None, session2=None, session3=None):
        session1 = session1.handle if session1 else lib.ESYS_TR_NONE
        session2 = session2.handle if session2 else lib.ESYS_TR_NONE
        session3 = session3.handle if session3 else lib.ESYS_TR_NONE
        _chkrc(lib.Esys_PolicyAuthorizeNV(self.ctx,
                                           authHandle.handle,
                                           nvIndex.handle,
                                           policySession.handle,
                                           session1, session2, session3))

    def CreatePrimary(self,primaryHandle, inSensitive, inPublic, outsideInfo, creationPCR,
                      session1=None, session2=None, session3=None):
        session1 = session1.handle if session1 else lib.ESYS_TR_NONE
        session2 = session2.handle if session2 else lib.ESYS_TR_NONE
        session3 = session3.handle if session3 else lib.ESYS_TR_NONE
        objectHandle = ffi.new('ESYS_TR *')
        outPublic = ffi.new('TPM2B_PUBLIC **')
        creationData = ffi.new('TPM2B_CREATION_DATA **')
        creationHash = ffi.new('TPM2B_DIGEST **')
        creationTicket = ffi.new('TPMT_TK_CREATION **')
        _chkrc(lib.Esys_CreatePrimary(self.ctx,
                                       primaryHandle.handle,
                                       session1, session2, session3,
                                       inSensitive,
                                       inPublic,
                                       outsideInfo,
                                       creationPCR,
                                       objectHandle,
                                       outPublic,
                                       creationData,
                                       creationHash,
                                       creationTicket)) 
        objectHandleObject = EsysTr(self, objectHandle[0])
        return(objectHandleObject, outPublic[0], creationData[0], creationHash[0], creationTicket[0])

    def HierarchyControl(self,authHandle, enable, state,
                         session1=None, session2=None, session3=None):
        session1 = session1.handle if session1 else lib.ESYS_TR_NONE
        session2 = session2.handle if session2 else lib.ESYS_TR_NONE
        session3 = session3.handle if session3 else lib.ESYS_TR_NONE
        _chkrc(lib.Esys_HierarchyControl(self.ctx,
                                          authHandle.handle,
                                          session1, session2, session3,
                                          enable,
                                          state))

    def SetPrimaryPolicy(self,authHandle, authPolicy, hashAlg,
                         session1=None, session2=None, session3=None):
        session1 = session1.handle if session1 else lib.ESYS_TR_NONE
        session2 = session2.handle if session2 else lib.ESYS_TR_NONE
        session3 = session3.handle if session3 else lib.ESYS_TR_NONE
        _chkrc(lib.Esys_SetPrimaryPolicy(self.ctx,
                                          authHandle.handle,
                                          session1, session2, session3,
                                          authPolicy,
                                          hashAlg))

    def ChangePPS(self,authHandle,
                  session1=None, session2=None, session3=None):
        session1 = session1.handle if session1 else lib.ESYS_TR_NONE
        session2 = session2.handle if session2 else lib.ESYS_TR_NONE
        session3 = session3.handle if session3 else lib.ESYS_TR_NONE
        _chkrc(lib.Esys_ChangePPS(self.ctx,
                                   authHandle.handle,
                                   session1, session2, session3))

    def ChangeEPS(self,authHandle,
                  session1=None, session2=None, session3=None):
        session1 = session1.handle if session1 else lib.ESYS_TR_NONE
        session2 = session2.handle if session2 else lib.ESYS_TR_NONE
        session3 = session3.handle if session3 else lib.ESYS_TR_NONE
        _chkrc(lib.Esys_ChangeEPS(self.ctx,
                                   authHandle.handle,
                                   session1, session2, session3))

    def Clear(self,authHandle,
              session1=None, session2=None, session3=None):
        session1 = session1.handle if session1 else lib.ESYS_TR_NONE
        session2 = session2.handle if session2 else lib.ESYS_TR_NONE
        session3 = session3.handle if session3 else lib.ESYS_TR_NONE
        _chkrc(lib.Esys_Clear(self.ctx,
                               authHandle.handle,
                               session1, session2, session3))

    def ClearControl(self,auth, disable,
                     session1=None, session2=None, session3=None):
        session1 = session1.handle if session1 else lib.ESYS_TR_NONE
        session2 = session2.handle if session2 else lib.ESYS_TR_NONE
        session3 = session3.handle if session3 else lib.ESYS_TR_NONE
        _chkrc(lib.Esys_ClearControl(self.ctx,
                                      auth.handle,
                                      session1, session2, session3,
                                      disable))

    def HierarchyChangeAuth(self,authHandle, newAuth,
                            session1=None, session2=None, session3=None):
        session1 = session1.handle if session1 else lib.ESYS_TR_NONE
        session2 = session2.handle if session2 else lib.ESYS_TR_NONE
        session3 = session3.handle if session3 else lib.ESYS_TR_NONE
        _chkrc(lib.Esys_HierarchyChangeAuth(self.ctx,
                                             authHandle.handle,
                                             session1, session2, session3,
                                             newAuth))

    def DictionaryAttackLockReset(self,lockHandle,
                                  session1=None, session2=None, session3=None):
        session1 = session1.handle if session1 else lib.ESYS_TR_NONE
        session2 = session2.handle if session2 else lib.ESYS_TR_NONE
        session3 = session3.handle if session3 else lib.ESYS_TR_NONE
        _chkrc(lib.Esys_DictionaryAttackLockReset(self.ctx,
                                                   lockHandle.handle,
                                                   session1, session2, session3))

    def DictionaryAttackParameters(self,lockHandle, newMaxTries, newRecoveryTime, lockoutRecovery,
                                   session1=None, session2=None, session3=None):
        session1 = session1.handle if session1 else lib.ESYS_TR_NONE
        session2 = session2.handle if session2 else lib.ESYS_TR_NONE
        session3 = session3.handle if session3 else lib.ESYS_TR_NONE
        _chkrc(lib.Esys_DictionaryAttackParameters(self.ctx,
                                                    lockHandle.handle,
                                                    session1, session2, session3,
                                                    newMaxTries,
                                                    newRecoveryTime,
                                                    lockoutRecovery))

    def PP_Commands(self,auth, setList, clearList,
                    session1=None, session2=None, session3=None):
        session1 = session1.handle if session1 else lib.ESYS_TR_NONE
        session2 = session2.handle if session2 else lib.ESYS_TR_NONE
        session3 = session3.handle if session3 else lib.ESYS_TR_NONE
        _chkrc(lib.Esys_PP_Commands(self.ctx,
                                     auth.handle,
                                     session1, session2, session3,
                                     setList,
                                     clearList))

    def SetAlgorithmSet(self,authHandle, algorithmSet,
                        session1=None, session2=None, session3=None):
        session1 = session1.handle if session1 else lib.ESYS_TR_NONE
        session2 = session2.handle if session2 else lib.ESYS_TR_NONE
        session3 = session3.handle if session3 else lib.ESYS_TR_NONE
        _chkrc(lib.Esys_SetAlgorithmSet(self.ctx,
                                         authHandle.handle,
                                         session1, session2, session3,
                                         algorithmSet))

    def FieldUpgradeStart(self,authorization,keyHandle, fuDigest, manifestSignature,
                          session1=None, session2=None, session3=None):
        session1 = session1.handle if session1 else lib.ESYS_TR_NONE
        session2 = session2.handle if session2 else lib.ESYS_TR_NONE
        session3 = session3.handle if session3 else lib.ESYS_TR_NONE
        _chkrc(lib.Esys_FieldUpgradeStart(self.ctx,
                                           authorization.handle,
                                           keyHandle.handle,
                                           session1, session2, session3,
                                           fuDigest,
                                           manifestSignature))

    def FieldUpgradeData(self, fuData,
                         session1=None, session2=None, session3=None):
        session1 = session1.handle if session1 else lib.ESYS_TR_NONE
        session2 = session2.handle if session2 else lib.ESYS_TR_NONE
        session3 = session3.handle if session3 else lib.ESYS_TR_NONE
        nextDigest = ffi.new('TPMT_HA **')
        firstDigest = ffi.new('TPMT_HA **')
        _chkrc(lib.Esys_FieldUpgradeData(self.ctx,
                                          session1, session2, session3,
                                          fuData,
                                          nextDigest,
                                          firstDigest))
        return(nextDigest[0], firstDigest[0])

    def FirmwareRead(self, sequenceNumber,
                     session1=None, session2=None, session3=None):
        session1 = session1.handle if session1 else lib.ESYS_TR_NONE
        session2 = session2.handle if session2 else lib.ESYS_TR_NONE
        session3 = session3.handle if session3 else lib.ESYS_TR_NONE
        fuData = ffi.new('TPM2B_MAX_BUFFER **')
        _chkrc(lib.Esys_FirmwareRead(self.ctx,
                                      session1, session2, session3,
                                      sequenceNumber,
                                      fuData))
        return(fuData[0])

    def ContextSave(self,saveHandle):
        context = ffi.new('TPMS_CONTEXT **')
        _chkrc(lib.Esys_ContextSave(self.ctx,
                                     saveHandle.handle,
                                     context))
        return(context[0])

    def ContextLoad(self, context):
        loadedHandle = ffi.new('ESYS_TR *')
        _chkrc(lib.Esys_ContextLoad(self.ctx,
                                     context,
                                     loadedHandle)) 
        loadedHandleObject = EsysTr(self, loadedHandle[0])
        return(loadedHandleObject)

    def FlushContext(self,flushHandle):
        _chkrc(lib.Esys_FlushContext(self.ctx,
                                      flushHandle.handle))

    def EvictControl(self,auth,objectHandle, persistentHandle,
                     session1=None, session2=None, session3=None):
        session1 = session1.handle if session1 else lib.ESYS_TR_NONE
        session2 = session2.handle if session2 else lib.ESYS_TR_NONE
        session3 = session3.handle if session3 else lib.ESYS_TR_NONE
        newObjectHandle = ffi.new('ESYS_TR *')
        _chkrc(lib.Esys_EvictControl(self.ctx,
                                      auth.handle,
                                      objectHandle.handle,
                                      session1, session2, session3,
                                      persistentHandle,
                                      newObjectHandle)) 
        newObjectHandleObject = EsysTr(self, newObjectHandle[0])
        return(newObjectHandleObject)

    def ReadClock(self,
                  session1=None, session2=None, session3=None):
        session1 = session1.handle if session1 else lib.ESYS_TR_NONE
        session2 = session2.handle if session2 else lib.ESYS_TR_NONE
        session3 = session3.handle if session3 else lib.ESYS_TR_NONE
        currentTime = ffi.new('TPMS_TIME_INFO **')
        _chkrc(lib.Esys_ReadClock(self.ctx,
                                   session1, session2, session3,
                                   currentTime))
        return(currentTime[0])

    def ClockSet(self,auth, newTime,
                 session1=None, session2=None, session3=None):
        session1 = session1.handle if session1 else lib.ESYS_TR_NONE
        session2 = session2.handle if session2 else lib.ESYS_TR_NONE
        session3 = session3.handle if session3 else lib.ESYS_TR_NONE
        _chkrc(lib.Esys_ClockSet(self.ctx,
                                  auth.handle,
                                  session1, session2, session3,
                                  newTime))

    def ClockRateAdjust(self,auth, rateAdjust,
                        session1=None, session2=None, session3=None):
        session1 = session1.handle if session1 else lib.ESYS_TR_NONE
        session2 = session2.handle if session2 else lib.ESYS_TR_NONE
        session3 = session3.handle if session3 else lib.ESYS_TR_NONE
        _chkrc(lib.Esys_ClockRateAdjust(self.ctx,
                                         auth.handle,
                                         session1, session2, session3,
                                         rateAdjust))

    def GetCapability(self, capability, property, propertyCount,
                      session1=None, session2=None, session3=None):
        session1 = session1.handle if session1 else lib.ESYS_TR_NONE
        session2 = session2.handle if session2 else lib.ESYS_TR_NONE
        session3 = session3.handle if session3 else lib.ESYS_TR_NONE
        moreData = ffi.new('TPMI_YES_NO *')
        capabilityData = ffi.new('TPMS_CAPABILITY_DATA **')
        _chkrc(lib.Esys_GetCapability(self.ctx,
                                       session1, session2, session3,
                                       capability,
                                       property,
                                       propertyCount,
                                       moreData,
                                       capabilityData))
        return(moreData[0], capabilityData[0])

    def TestParms(self, parameters,
                  session1=None, session2=None, session3=None):
        session1 = session1.handle if session1 else lib.ESYS_TR_NONE
        session2 = session2.handle if session2 else lib.ESYS_TR_NONE
        session3 = session3.handle if session3 else lib.ESYS_TR_NONE
        _chkrc(lib.Esys_TestParms(self.ctx,
                                   session1, session2, session3,
                                   parameters))

    def NV_DefineSpace(self,authHandle, auth, publicInfo,
                       session1=None, session2=None, session3=None):
        session1 = session1.handle if session1 else lib.ESYS_TR_NONE
        session2 = session2.handle if session2 else lib.ESYS_TR_NONE
        session3 = session3.handle if session3 else lib.ESYS_TR_NONE
        nvHandle = ffi.new('ESYS_TR *')
        _chkrc(lib.Esys_NV_DefineSpace(self.ctx,
                                        authHandle.handle,
                                        session1, session2, session3,
                                        auth,
                                        publicInfo,
                                        nvHandle)) 
        nvHandleObject = EsysTr(self, nvHandle[0])
        return(nvHandleObject)

    def NV_UndefineSpace(self,authHandle,nvIndex,
                         session1=None, session2=None, session3=None):
        session1 = session1.handle if session1 else lib.ESYS_TR_NONE
        session2 = session2.handle if session2 else lib.ESYS_TR_NONE
        session3 = session3.handle if session3 else lib.ESYS_TR_NONE
        _chkrc(lib.Esys_NV_UndefineSpace(self.ctx,
                                          authHandle.handle,
                                          nvIndex.handle,
                                          session1, session2, session3))

    def NV_UndefineSpaceSpecial(self,nvIndex,platform,
                                session1=None, session2=None, session3=None):
        session1 = session1.handle if session1 else lib.ESYS_TR_NONE
        session2 = session2.handle if session2 else lib.ESYS_TR_NONE
        session3 = session3.handle if session3 else lib.ESYS_TR_NONE
        _chkrc(lib.Esys_NV_UndefineSpaceSpecial(self.ctx,
                                                 nvIndex.handle,
                                                 platform.handle,
                                                 session1, session2, session3))

    def NV_ReadPublic(self,nvIndex,
                      session1=None, session2=None, session3=None):
        session1 = session1.handle if session1 else lib.ESYS_TR_NONE
        session2 = session2.handle if session2 else lib.ESYS_TR_NONE
        session3 = session3.handle if session3 else lib.ESYS_TR_NONE
        nvPublic = ffi.new('TPM2B_NV_PUBLIC **')
        nvName = ffi.new('TPM2B_NAME **')
        _chkrc(lib.Esys_NV_ReadPublic(self.ctx,
                                       nvIndex.handle,
                                       session1, session2, session3,
                                       nvPublic,
                                       nvName))
        return(nvPublic[0], nvName[0])

    def NV_Write(self,authHandle,nvIndex, data, offset,
                 session1=None, session2=None, session3=None):
        session1 = session1.handle if session1 else lib.ESYS_TR_NONE
        session2 = session2.handle if session2 else lib.ESYS_TR_NONE
        session3 = session3.handle if session3 else lib.ESYS_TR_NONE
        _chkrc(lib.Esys_NV_Write(self.ctx,
                                  authHandle.handle,
                                  nvIndex.handle,
                                  session1, session2, session3,
                                  data,
                                  offset))

    def NV_Increment(self,authHandle,nvIndex,
                     session1=None, session2=None, session3=None):
        session1 = session1.handle if session1 else lib.ESYS_TR_NONE
        session2 = session2.handle if session2 else lib.ESYS_TR_NONE
        session3 = session3.handle if session3 else lib.ESYS_TR_NONE
        _chkrc(lib.Esys_NV_Increment(self.ctx,
                                      authHandle.handle,
                                      nvIndex.handle,
                                      session1, session2, session3))

    def NV_Extend(self,authHandle,nvIndex, data,
                  session1=None, session2=None, session3=None):
        session1 = session1.handle if session1 else lib.ESYS_TR_NONE
        session2 = session2.handle if session2 else lib.ESYS_TR_NONE
        session3 = session3.handle if session3 else lib.ESYS_TR_NONE
        _chkrc(lib.Esys_NV_Extend(self.ctx,
                                   authHandle.handle,
                                   nvIndex.handle,
                                   session1, session2, session3,
                                   data))

    def NV_SetBits(self,authHandle,nvIndex, bits,
                   session1=None, session2=None, session3=None):
        session1 = session1.handle if session1 else lib.ESYS_TR_NONE
        session2 = session2.handle if session2 else lib.ESYS_TR_NONE
        session3 = session3.handle if session3 else lib.ESYS_TR_NONE
        _chkrc(lib.Esys_NV_SetBits(self.ctx,
                                    authHandle.handle,
                                    nvIndex.handle,
                                    session1, session2, session3,
                                    bits))

    def NV_WriteLock(self,authHandle,nvIndex,
                     session1=None, session2=None, session3=None):
        session1 = session1.handle if session1 else lib.ESYS_TR_NONE
        session2 = session2.handle if session2 else lib.ESYS_TR_NONE
        session3 = session3.handle if session3 else lib.ESYS_TR_NONE
        _chkrc(lib.Esys_NV_WriteLock(self.ctx,
                                      authHandle.handle,
                                      nvIndex.handle,
                                      session1, session2, session3))

    def NV_GlobalWriteLock(self,authHandle,
                           session1=None, session2=None, session3=None):
        session1 = session1.handle if session1 else lib.ESYS_TR_NONE
        session2 = session2.handle if session2 else lib.ESYS_TR_NONE
        session3 = session3.handle if session3 else lib.ESYS_TR_NONE
        _chkrc(lib.Esys_NV_GlobalWriteLock(self.ctx,
                                            authHandle.handle,
                                            session1, session2, session3))

    def NV_Read(self,authHandle,nvIndex, size, offset,
                session1=None, session2=None, session3=None):
        session1 = session1.handle if session1 else lib.ESYS_TR_NONE
        session2 = session2.handle if session2 else lib.ESYS_TR_NONE
        session3 = session3.handle if session3 else lib.ESYS_TR_NONE
        data = ffi.new('TPM2B_MAX_NV_BUFFER **')
        _chkrc(lib.Esys_NV_Read(self.ctx,
                                 authHandle.handle,
                                 nvIndex.handle,
                                 session1, session2, session3,
                                 size,
                                 offset,
                                 data))
        return(data[0])

    def NV_ReadLock(self,authHandle,nvIndex,
                    session1=None, session2=None, session3=None):
        session1 = session1.handle if session1 else lib.ESYS_TR_NONE
        session2 = session2.handle if session2 else lib.ESYS_TR_NONE
        session3 = session3.handle if session3 else lib.ESYS_TR_NONE
        _chkrc(lib.Esys_NV_ReadLock(self.ctx,
                                     authHandle.handle,
                                     nvIndex.handle,
                                     session1, session2, session3))

    def NV_ChangeAuth(self,nvIndex, newAuth,
                      session1=None, session2=None, session3=None):
        session1 = session1.handle if session1 else lib.ESYS_TR_NONE
        session2 = session2.handle if session2 else lib.ESYS_TR_NONE
        session3 = session3.handle if session3 else lib.ESYS_TR_NONE
        _chkrc(lib.Esys_NV_ChangeAuth(self.ctx,
                                       nvIndex.handle,
                                       session1, session2, session3,
                                       newAuth))

    def NV_Certify(self,signHandle,authHandle,nvIndex, qualifyingData, inScheme, size, offset,
                   session1=None, session2=None, session3=None):
        session1 = session1.handle if session1 else lib.ESYS_TR_NONE
        session2 = session2.handle if session2 else lib.ESYS_TR_NONE
        session3 = session3.handle if session3 else lib.ESYS_TR_NONE
        certifyInfo = ffi.new('TPM2B_ATTEST **')
        signature = ffi.new('TPMT_SIGNATURE **')
        _chkrc(lib.Esys_NV_Certify(self.ctx,
                                    signHandle.handle,
                                    authHandle.handle,
                                    nvIndex.handle,
                                    session1, session2, session3,
                                    qualifyingData,
                                    inScheme,
                                    size,
                                    offset,
                                    certifyInfo,
                                    signature))
        return(certifyInfo[0], signature[0])

    def Vendor_TCG_Test(self, inputData,
                        session1=None, session2=None, session3=None):
        session1 = session1.handle if session1 else lib.ESYS_TR_NONE
        session2 = session2.handle if session2 else lib.ESYS_TR_NONE
        session3 = session3.handle if session3 else lib.ESYS_TR_NONE
        outputData = ffi.new('TPM2B_DATA **')
        _chkrc(lib.Esys_Vendor_TCG_Test(self.ctx,
                                         session1, session2, session3,
                                         inputData,
                                         outputData))
        return(outputData[0])


#### Static ESYS_TR defines ####

class ESYS_TR:
    NONE = EsysTr(None, lib.ESYS_TR_NONE)
    PASSWORD = EsysTr(None, lib.ESYS_TR_PASSWORD)
    """ Access via e=ESYS_CONTEXT() => e.tr.NONE or similar """
    def __init__(self, ctx):
        self.PCR0 = EsysTr (ctx, lib.ESYS_TR_PCR0)
        self.PCR1 = EsysTr (ctx, lib.ESYS_TR_PCR1)
        self.PCR2 = EsysTr (ctx, lib.ESYS_TR_PCR2)
        self.PCR3 = EsysTr (ctx, lib.ESYS_TR_PCR3)
        self.PCR4 = EsysTr (ctx, lib.ESYS_TR_PCR4)
        self.PCR5 = EsysTr (ctx, lib.ESYS_TR_PCR5)
        self.PCR6 = EsysTr (ctx, lib.ESYS_TR_PCR6)
        self.PCR7 = EsysTr (ctx, lib.ESYS_TR_PCR7)
        self.PCR8 = EsysTr (ctx, lib.ESYS_TR_PCR8)
        self.PCR9 = EsysTr (ctx, lib.ESYS_TR_PCR9)
        self.PCR10 = EsysTr (ctx, lib.ESYS_TR_PCR10)
        self.PCR11 = EsysTr (ctx, lib.ESYS_TR_PCR11)
        self.PCR12 = EsysTr (ctx, lib.ESYS_TR_PCR12)
        self.PCR13 = EsysTr (ctx, lib.ESYS_TR_PCR13)
        self.PCR14 = EsysTr (ctx, lib.ESYS_TR_PCR14)
        self.PCR15 = EsysTr (ctx, lib.ESYS_TR_PCR15)
        self.PCR16 = EsysTr (ctx, lib.ESYS_TR_PCR16)
        self.PCR17 = EsysTr (ctx, lib.ESYS_TR_PCR17)
        self.PCR18 = EsysTr (ctx, lib.ESYS_TR_PCR18)
        self.PCR19 = EsysTr (ctx, lib.ESYS_TR_PCR19)
        self.PCR20 = EsysTr (ctx, lib.ESYS_TR_PCR20)
        self.PCR21 = EsysTr (ctx, lib.ESYS_TR_PCR21)
        self.PCR22 = EsysTr (ctx, lib.ESYS_TR_PCR22)
        self.PCR23 = EsysTr (ctx, lib.ESYS_TR_PCR23)
        self.PCR24 = EsysTr (ctx, lib.ESYS_TR_PCR24)
        self.PCR25 = EsysTr (ctx, lib.ESYS_TR_PCR25)
        self.PCR26 = EsysTr (ctx, lib.ESYS_TR_PCR26)
        self.PCR27 = EsysTr (ctx, lib.ESYS_TR_PCR27)
        self.PCR28 = EsysTr (ctx, lib.ESYS_TR_PCR28)
        self.PCR29 = EsysTr (ctx, lib.ESYS_TR_PCR29)
        self.PCR30 = EsysTr (ctx, lib.ESYS_TR_PCR30)
        self.PCR31 = EsysTr (ctx, lib.ESYS_TR_PCR31)
        self.OWNER = EsysTr (ctx, lib.ESYS_TR_RH_OWNER)
        self.NULL = EsysTr (ctx, lib.ESYS_TR_RH_NULL)
        self.LOCKOUT = EsysTr (ctx, lib.ESYS_TR_RH_LOCKOUT)
        self.ENDORSEMENT = EsysTr (ctx, lib.ESYS_TR_RH_ENDORSEMENT)
        self.PLATFORM = EsysTr (ctx, lib.ESYS_TR_RH_PLATFORM)
        self.PLATFORM_NV = EsysTr (ctx, lib.ESYS_TR_RH_PLATFORM_NV)
        self.RH_OWNER = EsysTr (ctx, lib.ESYS_TR_RH_OWNER)
        self.RH_NULL = EsysTr (ctx, lib.ESYS_TR_RH_NULL)
        self.RH_LOCKOUT = EsysTr (ctx, lib.ESYS_TR_RH_LOCKOUT)
        self.RH_ENDORSEMENT = EsysTr (ctx, lib.ESYS_TR_RH_ENDORSEMENT)
        self.RH_PLATFORM = EsysTr (ctx, lib.ESYS_TR_RH_PLATFORM)
        self.RH_PLATFORM_NV = EsysTr (ctx, lib.ESYS_TR_RH_PLATFORM_NV)

#### Provide defines for constants ####

class TPM2_ALG(int):
    ERROR = lib.TPM2_ALG_ERROR
    RSA = lib.TPM2_ALG_RSA
    SHA = lib.TPM2_ALG_SHA
    SHA1 = lib.TPM2_ALG_SHA1
    HMAC = lib.TPM2_ALG_HMAC
    AES = lib.TPM2_ALG_AES
    MGF1 = lib.TPM2_ALG_MGF1
    KEYEDHASH = lib.TPM2_ALG_KEYEDHASH
    XOR = lib.TPM2_ALG_XOR
    SHA256 = lib.TPM2_ALG_SHA256
    SHA384 = lib.TPM2_ALG_SHA384
    SHA512 = lib.TPM2_ALG_SHA512
    NULL = lib.TPM2_ALG_NULL
    SM3_256 = lib.TPM2_ALG_SM3_256
    SM4 = lib.TPM2_ALG_SM4
    RSASSA = lib.TPM2_ALG_RSASSA
    RSAES = lib.TPM2_ALG_RSAES
    RSAPSS = lib.TPM2_ALG_RSAPSS
    OAEP = lib.TPM2_ALG_OAEP
    ECDSA = lib.TPM2_ALG_ECDSA
    ECDH = lib.TPM2_ALG_ECDH
    ECDAA = lib.TPM2_ALG_ECDAA
    SM2 = lib.TPM2_ALG_SM2
    ECSCHNORR = lib.TPM2_ALG_ECSCHNORR
    ECMQV = lib.TPM2_ALG_ECMQV
    KDF1_SP800_56A = lib.TPM2_ALG_KDF1_SP800_56A
    KDF2 = lib.TPM2_ALG_KDF2
    KDF1_SP800_108 = lib.TPM2_ALG_KDF1_SP800_108
    ECC = lib.TPM2_ALG_ECC
    SYMCIPHER = lib.TPM2_ALG_SYMCIPHER
    CAMELLIA = lib.TPM2_ALG_CAMELLIA
    CTR = lib.TPM2_ALG_CTR
    SHA3_256 = lib.TPM2_ALG_SHA3_256
    SHA3_384 = lib.TPM2_ALG_SHA3_384
    SHA3_512 = lib.TPM2_ALG_SHA3_512
    OFB = lib.TPM2_ALG_OFB
    CBC = lib.TPM2_ALG_CBC
    CFB = lib.TPM2_ALG_CFB
    ECB = lib.TPM2_ALG_ECB
    FIRST = lib.TPM2_ALG_FIRST
    LAST = lib.TPM2_ALG_LAST
TPM2_ALG_ID = TPM2_ALG

class TPM2_ECC(int):
    NONE = lib.TPM2_ECC_NONE
    NIST_P192 = lib.TPM2_ECC_NIST_P192
    NIST_P224 = lib.TPM2_ECC_NIST_P224
    NIST_P256 = lib.TPM2_ECC_NIST_P256
    NIST_P384 = lib.TPM2_ECC_NIST_P384
    NIST_P521 = lib.TPM2_ECC_NIST_P521
    BN_P256 = lib.TPM2_ECC_BN_P256
    BN_P638 = lib.TPM2_ECC_BN_P638
    SM2_P256 = lib.TPM2_ECC_SM2_P256
TPM2_ECC_CURVE = TPM2_ECC

class TPM2_CC(int):
    NV_UndefineSpaceSpecial = lib.TPM2_CC_NV_UndefineSpaceSpecial
    FIRST = lib.TPM2_CC_FIRST
    EvictControl = lib.TPM2_CC_EvictControl
    HierarchyControl = lib.TPM2_CC_HierarchyControl
    NV_UndefineSpace = lib.TPM2_CC_NV_UndefineSpace
    ChangeEPS = lib.TPM2_CC_ChangeEPS
    ChangePPS = lib.TPM2_CC_ChangePPS
    Clear = lib.TPM2_CC_Clear
    ClearControl = lib.TPM2_CC_ClearControl
    ClockSet = lib.TPM2_CC_ClockSet
    HierarchyChangeAuth = lib.TPM2_CC_HierarchyChangeAuth
    NV_DefineSpace = lib.TPM2_CC_NV_DefineSpace
    PCR_Allocate = lib.TPM2_CC_PCR_Allocate
    PCR_SetAuthPolicy = lib.TPM2_CC_PCR_SetAuthPolicy
    PP_Commands = lib.TPM2_CC_PP_Commands
    SetPrimaryPolicy = lib.TPM2_CC_SetPrimaryPolicy
    FieldUpgradeStart = lib.TPM2_CC_FieldUpgradeStart
    ClockRateAdjust = lib.TPM2_CC_ClockRateAdjust
    CreatePrimary = lib.TPM2_CC_CreatePrimary
    NV_GlobalWriteLock = lib.TPM2_CC_NV_GlobalWriteLock
    GetCommandAuditDigest = lib.TPM2_CC_GetCommandAuditDigest
    NV_Increment = lib.TPM2_CC_NV_Increment
    NV_SetBits = lib.TPM2_CC_NV_SetBits
    NV_Extend = lib.TPM2_CC_NV_Extend
    NV_Write = lib.TPM2_CC_NV_Write
    NV_WriteLock = lib.TPM2_CC_NV_WriteLock
    DictionaryAttackLockReset = lib.TPM2_CC_DictionaryAttackLockReset
    DictionaryAttackParameters = lib.TPM2_CC_DictionaryAttackParameters
    NV_ChangeAuth = lib.TPM2_CC_NV_ChangeAuth
    PCR_Event = lib.TPM2_CC_PCR_Event
    PCR_Reset = lib.TPM2_CC_PCR_Reset
    SequenceComplete = lib.TPM2_CC_SequenceComplete
    SetAlgorithmSet = lib.TPM2_CC_SetAlgorithmSet
    SetCommandCodeAuditStatus = lib.TPM2_CC_SetCommandCodeAuditStatus
    FieldUpgradeData = lib.TPM2_CC_FieldUpgradeData
    IncrementalSelfTest = lib.TPM2_CC_IncrementalSelfTest
    SelfTest = lib.TPM2_CC_SelfTest
    Startup = lib.TPM2_CC_Startup
    Shutdown = lib.TPM2_CC_Shutdown
    StirRandom = lib.TPM2_CC_StirRandom
    ActivateCredential = lib.TPM2_CC_ActivateCredential
    Certify = lib.TPM2_CC_Certify
    PolicyNV = lib.TPM2_CC_PolicyNV
    CertifyCreation = lib.TPM2_CC_CertifyCreation
    Duplicate = lib.TPM2_CC_Duplicate
    GetTime = lib.TPM2_CC_GetTime
    GetSessionAuditDigest = lib.TPM2_CC_GetSessionAuditDigest
    NV_Read = lib.TPM2_CC_NV_Read
    NV_ReadLock = lib.TPM2_CC_NV_ReadLock
    ObjectChangeAuth = lib.TPM2_CC_ObjectChangeAuth
    PolicySecret = lib.TPM2_CC_PolicySecret
    Rewrap = lib.TPM2_CC_Rewrap
    Create = lib.TPM2_CC_Create
    ECDH_ZGen = lib.TPM2_CC_ECDH_ZGen
    HMAC = lib.TPM2_CC_HMAC
    Import = lib.TPM2_CC_Import
    Load = lib.TPM2_CC_Load
    Quote = lib.TPM2_CC_Quote
    RSA_Decrypt = lib.TPM2_CC_RSA_Decrypt
    HMAC_Start = lib.TPM2_CC_HMAC_Start
    SequenceUpdate = lib.TPM2_CC_SequenceUpdate
    Sign = lib.TPM2_CC_Sign
    Unseal = lib.TPM2_CC_Unseal
    PolicySigned = lib.TPM2_CC_PolicySigned
    ContextLoad = lib.TPM2_CC_ContextLoad
    ContextSave = lib.TPM2_CC_ContextSave
    ECDH_KeyGen = lib.TPM2_CC_ECDH_KeyGen
    EncryptDecrypt = lib.TPM2_CC_EncryptDecrypt
    FlushContext = lib.TPM2_CC_FlushContext
    LoadExternal = lib.TPM2_CC_LoadExternal
    MakeCredential = lib.TPM2_CC_MakeCredential
    NV_ReadPublic = lib.TPM2_CC_NV_ReadPublic
    PolicyAuthorize = lib.TPM2_CC_PolicyAuthorize
    PolicyAuthValue = lib.TPM2_CC_PolicyAuthValue
    PolicyCommandCode = lib.TPM2_CC_PolicyCommandCode
    PolicyCounterTimer = lib.TPM2_CC_PolicyCounterTimer
    PolicyCpHash = lib.TPM2_CC_PolicyCpHash
    PolicyLocality = lib.TPM2_CC_PolicyLocality
    PolicyNameHash = lib.TPM2_CC_PolicyNameHash
    PolicyOR = lib.TPM2_CC_PolicyOR
    PolicyTicket = lib.TPM2_CC_PolicyTicket
    ReadPublic = lib.TPM2_CC_ReadPublic
    RSA_Encrypt = lib.TPM2_CC_RSA_Encrypt
    StartAuthSession = lib.TPM2_CC_StartAuthSession
    VerifySignature = lib.TPM2_CC_VerifySignature
    ECC_Parameters = lib.TPM2_CC_ECC_Parameters
    FirmwareRead = lib.TPM2_CC_FirmwareRead
    GetCapability = lib.TPM2_CC_GetCapability
    GetRandom = lib.TPM2_CC_GetRandom
    GetTestResult = lib.TPM2_CC_GetTestResult
    Hash = lib.TPM2_CC_Hash
    PCR_Read = lib.TPM2_CC_PCR_Read
    PolicyPCR = lib.TPM2_CC_PolicyPCR
    PolicyRestart = lib.TPM2_CC_PolicyRestart
    ReadClock = lib.TPM2_CC_ReadClock
    PCR_Extend = lib.TPM2_CC_PCR_Extend
    PCR_SetAuthValue = lib.TPM2_CC_PCR_SetAuthValue
    NV_Certify = lib.TPM2_CC_NV_Certify
    EventSequenceComplete = lib.TPM2_CC_EventSequenceComplete
    HashSequenceStart = lib.TPM2_CC_HashSequenceStart
    PolicyPhysicalPresence = lib.TPM2_CC_PolicyPhysicalPresence
    PolicyDuplicationSelect = lib.TPM2_CC_PolicyDuplicationSelect
    PolicyGetDigest = lib.TPM2_CC_PolicyGetDigest
    TestParms = lib.TPM2_CC_TestParms
    Commit = lib.TPM2_CC_Commit
    PolicyPassword = lib.TPM2_CC_PolicyPassword
    ZGen_2Phase = lib.TPM2_CC_ZGen_2Phase
    EC_Ephemeral = lib.TPM2_CC_EC_Ephemeral
    PolicyNvWritten = lib.TPM2_CC_PolicyNvWritten
    PolicyTemplate = lib.TPM2_CC_PolicyTemplate
    CreateLoaded = lib.TPM2_CC_CreateLoaded
    PolicyAuthorizeNV = lib.TPM2_CC_PolicyAuthorizeNV
    EncryptDecrypt2 = lib.TPM2_CC_EncryptDecrypt2
    AC_GetCapability = lib.TPM2_CC_AC_GetCapability
    AC_Send = lib.TPM2_CC_AC_Send
    Policy_AC_SendSelect = lib.TPM2_CC_Policy_AC_SendSelect
    LAST = lib.TPM2_CC_LAST
    Vendor_TCG_Test = lib.TPM2_CC_Vendor_TCG_Test

class TPM2_SPEC(int):
    FAMILY = lib.TPM2_SPEC_FAMILY
    LEVEL = lib.TPM2_SPEC_LEVEL
    VERSION = lib.TPM2_SPEC_VERSION
    YEAR = lib.TPM2_SPEC_YEAR
    DAY_OF_YEAR = lib.TPM2_SPEC_DAY_OF_YEAR

class TPM2_GENERATED_VALUE(int):
    VALUE = lib.TPM2_GENERATED_VALUE

class TPM2_RC(int):
    SUCCESS = lib.TPM2_RC_SUCCESS
    BAD_TAG = lib.TPM2_RC_BAD_TAG
    VER1 = lib.TPM2_RC_VER1
    INITIALIZE = lib.TPM2_RC_INITIALIZE
    FAILURE = lib.TPM2_RC_FAILURE
    SEQUENCE = lib.TPM2_RC_SEQUENCE
    PRIVATE = lib.TPM2_RC_PRIVATE
    HMAC = lib.TPM2_RC_HMAC
    DISABLED = lib.TPM2_RC_DISABLED
    EXCLUSIVE = lib.TPM2_RC_EXCLUSIVE
    AUTH_TYPE = lib.TPM2_RC_AUTH_TYPE
    AUTH_MISSING = lib.TPM2_RC_AUTH_MISSING
    POLICY = lib.TPM2_RC_POLICY
    PCR = lib.TPM2_RC_PCR
    PCR_CHANGED = lib.TPM2_RC_PCR_CHANGED
    UPGRADE = lib.TPM2_RC_UPGRADE
    TOO_MANY_CONTEXTS = lib.TPM2_RC_TOO_MANY_CONTEXTS
    AUTH_UNAVAILABLE = lib.TPM2_RC_AUTH_UNAVAILABLE
    REBOOT = lib.TPM2_RC_REBOOT
    UNBALANCED = lib.TPM2_RC_UNBALANCED
    COMMAND_SIZE = lib.TPM2_RC_COMMAND_SIZE
    COMMAND_CODE = lib.TPM2_RC_COMMAND_CODE
    AUTHSIZE = lib.TPM2_RC_AUTHSIZE
    AUTH_CONTEXT = lib.TPM2_RC_AUTH_CONTEXT
    NV_RANGE = lib.TPM2_RC_NV_RANGE
    NV_SIZE = lib.TPM2_RC_NV_SIZE
    NV_LOCKED = lib.TPM2_RC_NV_LOCKED
    NV_AUTHORIZATION = lib.TPM2_RC_NV_AUTHORIZATION
    NV_UNINITIALIZED = lib.TPM2_RC_NV_UNINITIALIZED
    NV_SPACE = lib.TPM2_RC_NV_SPACE
    NV_DEFINED = lib.TPM2_RC_NV_DEFINED
    BAD_CONTEXT = lib.TPM2_RC_BAD_CONTEXT
    CPHASH = lib.TPM2_RC_CPHASH
    PARENT = lib.TPM2_RC_PARENT
    NEEDS_TEST = lib.TPM2_RC_NEEDS_TEST
    NO_RESULT = lib.TPM2_RC_NO_RESULT
    SENSITIVE = lib.TPM2_RC_SENSITIVE
    MAX_FM0 = lib.TPM2_RC_MAX_FM0
    FMT1 = lib.TPM2_RC_FMT1
    ASYMMETRIC = lib.TPM2_RC_ASYMMETRIC
    ATTRIBUTES = lib.TPM2_RC_ATTRIBUTES
    HASH = lib.TPM2_RC_HASH
    VALUE = lib.TPM2_RC_VALUE
    HIERARCHY = lib.TPM2_RC_HIERARCHY
    KEY_SIZE = lib.TPM2_RC_KEY_SIZE
    MGF = lib.TPM2_RC_MGF
    MODE = lib.TPM2_RC_MODE
    TYPE = lib.TPM2_RC_TYPE
    HANDLE = lib.TPM2_RC_HANDLE
    KDF = lib.TPM2_RC_KDF
    RANGE = lib.TPM2_RC_RANGE
    AUTH_FAIL = lib.TPM2_RC_AUTH_FAIL
    NONCE = lib.TPM2_RC_NONCE
    PP = lib.TPM2_RC_PP
    SCHEME = lib.TPM2_RC_SCHEME
    SIZE = lib.TPM2_RC_SIZE
    SYMMETRIC = lib.TPM2_RC_SYMMETRIC
    TAG = lib.TPM2_RC_TAG
    SELECTOR = lib.TPM2_RC_SELECTOR
    INSUFFICIENT = lib.TPM2_RC_INSUFFICIENT
    SIGNATURE = lib.TPM2_RC_SIGNATURE
    KEY = lib.TPM2_RC_KEY
    POLICY_FAIL = lib.TPM2_RC_POLICY_FAIL
    INTEGRITY = lib.TPM2_RC_INTEGRITY
    TICKET = lib.TPM2_RC_TICKET
    BAD_AUTH = lib.TPM2_RC_BAD_AUTH
    EXPIRED = lib.TPM2_RC_EXPIRED
    POLICY_CC = lib.TPM2_RC_POLICY_CC
    BINDING = lib.TPM2_RC_BINDING
    CURVE = lib.TPM2_RC_CURVE
    ECC_POINT = lib.TPM2_RC_ECC_POINT
    WARN = lib.TPM2_RC_WARN
    CONTEXT_GAP = lib.TPM2_RC_CONTEXT_GAP
    OBJECT_MEMORY = lib.TPM2_RC_OBJECT_MEMORY
    SESSION_MEMORY = lib.TPM2_RC_SESSION_MEMORY
    MEMORY = lib.TPM2_RC_MEMORY
    SESSION_HANDLES = lib.TPM2_RC_SESSION_HANDLES
    OBJECT_HANDLES = lib.TPM2_RC_OBJECT_HANDLES
    LOCALITY = lib.TPM2_RC_LOCALITY
    YIELDED = lib.TPM2_RC_YIELDED
    CANCELED = lib.TPM2_RC_CANCELED
    TESTING = lib.TPM2_RC_TESTING
    REFERENCE_H0 = lib.TPM2_RC_REFERENCE_H0
    REFERENCE_H1 = lib.TPM2_RC_REFERENCE_H1
    REFERENCE_H2 = lib.TPM2_RC_REFERENCE_H2
    REFERENCE_H3 = lib.TPM2_RC_REFERENCE_H3
    REFERENCE_H4 = lib.TPM2_RC_REFERENCE_H4
    REFERENCE_H5 = lib.TPM2_RC_REFERENCE_H5
    REFERENCE_H6 = lib.TPM2_RC_REFERENCE_H6
    REFERENCE_S0 = lib.TPM2_RC_REFERENCE_S0
    REFERENCE_S1 = lib.TPM2_RC_REFERENCE_S1
    REFERENCE_S2 = lib.TPM2_RC_REFERENCE_S2
    REFERENCE_S3 = lib.TPM2_RC_REFERENCE_S3
    REFERENCE_S4 = lib.TPM2_RC_REFERENCE_S4
    REFERENCE_S5 = lib.TPM2_RC_REFERENCE_S5
    REFERENCE_S6 = lib.TPM2_RC_REFERENCE_S6
    NV_RATE = lib.TPM2_RC_NV_RATE
    LOCKOUT = lib.TPM2_RC_LOCKOUT
    RETRY = lib.TPM2_RC_RETRY
    NV_UNAVAILABLE = lib.TPM2_RC_NV_UNAVAILABLE
    NOT_USED = lib.TPM2_RC_NOT_USED
    H = lib.TPM2_RC_H
    P = lib.TPM2_RC_P
    S = lib.TPM2_RC_S
    RC1 = lib.TPM2_RC_1
    RC2 = lib.TPM2_RC_2
    RC3 = lib.TPM2_RC_3
    RC4 = lib.TPM2_RC_4
    RC5 = lib.TPM2_RC_5
    RC6 = lib.TPM2_RC_6
    RC7 = lib.TPM2_RC_7
    RC8 = lib.TPM2_RC_8
    RC9 = lib.TPM2_RC_9
    A = lib.TPM2_RC_A
    B = lib.TPM2_RC_B
    C = lib.TPM2_RC_C
    D = lib.TPM2_RC_D
    E = lib.TPM2_RC_E
    F = lib.TPM2_RC_F
    N_MASK = lib.TPM2_RC_N_MASK

class TPM2_EO(int):
    EQ = lib.TPM2_EO_EQ
    NEQ = lib.TPM2_EO_NEQ
    SIGNED_GT = lib.TPM2_EO_SIGNED_GT
    UNSIGNED_GT = lib.TPM2_EO_UNSIGNED_GT
    SIGNED_LT = lib.TPM2_EO_SIGNED_LT
    UNSIGNED_LT = lib.TPM2_EO_UNSIGNED_LT
    SIGNED_GE = lib.TPM2_EO_SIGNED_GE
    UNSIGNED_GE = lib.TPM2_EO_UNSIGNED_GE
    SIGNED_LE = lib.TPM2_EO_SIGNED_LE
    UNSIGNED_LE = lib.TPM2_EO_UNSIGNED_LE
    BITSET = lib.TPM2_EO_BITSET
    BITCLEAR = lib.TPM2_EO_BITCLEAR

class TPM2_ST(int):
    RSP_COMMAND = lib.TPM2_ST_RSP_COMMAND
    NULL = lib.TPM2_ST_NULL
    NO_SESSIONS = lib.TPM2_ST_NO_SESSIONS
    SESSIONS = lib.TPM2_ST_SESSIONS
    ATTEST_NV = lib.TPM2_ST_ATTEST_NV
    ATTEST_COMMAND_AUDIT = lib.TPM2_ST_ATTEST_COMMAND_AUDIT
    ATTEST_SESSION_AUDIT = lib.TPM2_ST_ATTEST_SESSION_AUDIT
    ATTEST_CERTIFY = lib.TPM2_ST_ATTEST_CERTIFY
    ATTEST_QUOTE = lib.TPM2_ST_ATTEST_QUOTE
    ATTEST_TIME = lib.TPM2_ST_ATTEST_TIME
    ATTEST_CREATION = lib.TPM2_ST_ATTEST_CREATION
    CREATION = lib.TPM2_ST_CREATION
    VERIFIED = lib.TPM2_ST_VERIFIED
    AUTH_SECRET = lib.TPM2_ST_AUTH_SECRET
    HASHCHECK = lib.TPM2_ST_HASHCHECK
    AUTH_SIGNED = lib.TPM2_ST_AUTH_SIGNED
    FU_MANIFEST = lib.TPM2_ST_FU_MANIFEST

class TPM2_SU(int):
    CLEAR = lib.TPM2_SU_CLEAR
    STATE = lib.TPM2_SU_STATE

class TPM2_SE(int):
    HMAC = lib.TPM2_SE_HMAC
    POLICY = lib.TPM2_SE_POLICY
    TRIAL = lib.TPM2_SE_TRIAL

class TPM2_CAP(int):
    FIRST = lib.TPM2_CAP_FIRST
    ALGS = lib.TPM2_CAP_ALGS
    HANDLES = lib.TPM2_CAP_HANDLES
    COMMANDS = lib.TPM2_CAP_COMMANDS
    PP_COMMANDS = lib.TPM2_CAP_PP_COMMANDS
    AUDIT_COMMANDS = lib.TPM2_CAP_AUDIT_COMMANDS
    PCRS = lib.TPM2_CAP_PCRS
    TPM_PROPERTIES = lib.TPM2_CAP_TPM_PROPERTIES
    PCR_PROPERTIES = lib.TPM2_CAP_PCR_PROPERTIES
    ECC_CURVES = lib.TPM2_CAP_ECC_CURVES
    LAST = lib.TPM2_CAP_LAST
    VENDOR_PROPERTY = lib.TPM2_CAP_VENDOR_PROPERTY

class TPM2_PT(int):
    NONE = lib.TPM2_PT_NONE
    GROUP = lib.TPM2_PT_GROUP
    FIXED = lib.TPM2_PT_FIXED
#TODO    FAMILY_INDICATOR = lib.TPM2_PT_FAMILY_INDICATOR
#    LEVEL = lib.TPM2_PT_LEVEL
#    REVISION = lib.TPM2_PT_REVISION
#    DAY_OF_YEAR = lib.TPM2_PT_DAY_OF_YEAR
#    YEAR = lib.TPM2_PT_YEAR
#    MANUFACTURER = lib.TPM2_PT_MANUFACTURER
#    VENDOR_STRING_1 = lib.TPM2_PT_VENDOR_STRING_1
#    VENDOR_STRING_2 = lib.TPM2_PT_VENDOR_STRING_2
#    VENDOR_STRING_3 = lib.TPM2_PT_VENDOR_STRING_3
#    VENDOR_STRING_4 = lib.TPM2_PT_VENDOR_STRING_4
#    VENDOR_TPM_TYPE = lib.TPM2_PT_VENDOR_TPM_TYPE
#    FIRMWARE_VERSION_1 = lib.TPM2_PT_FIRMWARE_VERSION_1
#    FIRMWARE_VERSION_2 = lib.TPM2_PT_FIRMWARE_VERSION_2
#    INPUT_BUFFER = lib.TPM2_PT_INPUT_BUFFER
#    TPM2_HR_TRANSIENT_MIN = lib.TPM2_PT_TPM2_HR_TRANSIENT_MIN
#    TPM2_HR_PERSISTENT_MIN = lib.TPM2_PT_TPM2_HR_PERSISTENT_MIN
#    HR_LOADED_MIN = lib.TPM2_PT_HR_LOADED_MIN
#    ACTIVE_SESSIONS_MAX = lib.TPM2_PT_ACTIVE_SESSIONS_MAX
#    PCR_COUNT = lib.TPM2_PT_PCR_COUNT
#    PCR_SELECT_MIN = lib.TPM2_PT_PCR_SELECT_MIN
#    CONTEXT_GAP_MAX = lib.TPM2_PT_CONTEXT_GAP_MAX
#    NV_COUNTERS_MAX = lib.TPM2_PT_NV_COUNTERS_MAX
#    NV_INDEX_MAX = lib.TPM2_PT_NV_INDEX_MAX
#    MEMORY = lib.TPM2_PT_MEMORY
#    CLOCK_UPDATE = lib.TPM2_PT_CLOCK_UPDATE
#    CONTEXT_HASH = lib.TPM2_PT_CONTEXT_HASH
#    CONTEXT_SYM = lib.TPM2_PT_CONTEXT_SYM
#    CONTEXT_SYM_SIZE = lib.TPM2_PT_CONTEXT_SYM_SIZE
#    ORDERLY_COUNT = lib.TPM2_PT_ORDERLY_COUNT
#    MAX_COMMAND_SIZE = lib.TPM2_PT_MAX_COMMAND_SIZE
#    MAX_RESPONSE_SIZE = lib.TPM2_PT_MAX_RESPONSE_SIZE
#    MAX_DIGEST = lib.TPM2_PT_MAX_DIGEST
#    MAX_OBJECT_CONTEXT = lib.TPM2_PT_MAX_OBJECT_CONTEXT
#    MAX_SESSION_CONTEXT = lib.TPM2_PT_MAX_SESSION_CONTEXT
#    PS_FAMILY_INDICATOR = lib.TPM2_PT_PS_FAMILY_INDICATOR
#    PS_LEVEL = lib.TPM2_PT_PS_LEVEL
#    PS_REVISION = lib.TPM2_PT_PS_REVISION
#    PS_DAY_OF_YEAR = lib.TPM2_PT_PS_DAY_OF_YEAR
#    PS_YEAR = lib.TPM2_PT_PS_YEAR
#    SPLIT_MAX = lib.TPM2_PT_SPLIT_MAX
#    TOTAL_COMMANDS = lib.TPM2_PT_TOTAL_COMMANDS
#    LIBRARY_COMMANDS = lib.TPM2_PTlibRARY_COMMANDS
#    VENDOR_COMMANDS = lib.TPM2_PT_VENDOR_COMMANDS
#    NV_BUFFER_MAX = lib.TPM2_PT_NV_BUFFER_MAX
#    MODES = lib.TPM2_PT_MODES
#    VAR = lib.TPM2_PT_VAR
#    PERMANENT = lib.TPM2_PT_PERMANENT
#    STARTUP_CLEAR = lib.TPM2_PT_STARTUP_CLEAR
#    TPM2_HR_NV_INDEX = lib.TPM2_PT_TPM2_HR_NV_INDEX
#    HR_LOADED = lib.TPM2_PT_HR_LOADED
#    HR_LOADED_AVAIL = lib.TPM2_PT_HR_LOADED_AVAIL
#    HR_ACTIVE = lib.TPM2_PT_HR_ACTIVE
#    HR_ACTIVE_AVAIL = lib.TPM2_PT_HR_ACTIVE_AVAIL
#    TPM2_HR_TRANSIENT_AVAIL = lib.TPM2_PT_TPM2_HR_TRANSIENT_AVAIL
#    TPM2_HR_PERSISTENT = lib.TPM2_PT_TPM2_HR_PERSISTENT
#    TPM2_HR_PERSISTENT_AVAIL = lib.TPM2_PT_TPM2_HR_PERSISTENT_AVAIL
#    NV_COUNTERS = lib.TPM2_PT_NV_COUNTERS
#    NV_COUNTERS_AVAIL = lib.TPM2_PT_NV_COUNTERS_AVAIL
#    ALGORITHM_SET = lib.TPM2_PT_ALGORITHM_SET
#    LOADED_CURVES = lib.TPM2_PT_LOADED_CURVES
#    LOCKOUT_COUNTER = lib.TPM2_PT_LOCKOUT_COUNTER
#    MAX_AUTH_FAIL = lib.TPM2_PT_MAX_AUTH_FAIL
#    LOCKOUT_INTERVAL = lib.TPM2_PT_LOCKOUT_INTERVAL
#    LOCKOUT_RECOVERY = lib.TPM2_PT_LOCKOUT_RECOVERY
#    NV_WRITE_RECOVERY = lib.TPM2_PT_NV_WRITE_RECOVERY
#    AUDIT_COUNTER_0 = lib.TPM2_PT_AUDIT_COUNTER_0
#    AUDIT_COUNTER_1 = lib.TPM2_PT_AUDIT_COUNTER_1

class TPM2_PT_PCR(int):
    FIRST = lib.TPM2_PT_TPM2_PCR_FIRST
    SAVE = lib.TPM2_PT_PCR_SAVE
    EXTEND_L0 = lib.TPM2_PT_PCR_EXTEND_L0
    RESET_L0 = lib.TPM2_PT_PCR_RESET_L0
    EXTEND_L1 = lib.TPM2_PT_PCR_EXTEND_L1
    RESET_L1 = lib.TPM2_PT_PCR_RESET_L1
    EXTEND_L2 = lib.TPM2_PT_PCR_EXTEND_L2
    RESET_L2 = lib.TPM2_PT_PCR_RESET_L2
    EXTEND_L3 = lib.TPM2_PT_PCR_EXTEND_L3
    RESET_L3 = lib.TPM2_PT_PCR_RESET_L3
    EXTEND_L4 = lib.TPM2_PT_PCR_EXTEND_L4
    RESET_L4 = lib.TPM2_PT_PCR_RESET_L4
    NO_INCREMENT = lib.TPM2_PT_PCR_NO_INCREMENT
    DRTM_RESET = lib.TPM2_PT_PCR_DRTM_RESET
    POLICY = lib.TPM2_PT_PCR_POLICY
    AUTH = lib.TPM2_PT_PCR_AUTH
    LAST = lib.TPM2_PT_TPM2_PCR_LAST

class TPM2_PS(int):
    MAIN = lib.TPM2_PS_MAIN
    PC = lib.TPM2_PS_PC
    PDA = lib.TPM2_PS_PDA
    CELL_PHONE = lib.TPM2_PS_CELL_PHONE
    SERVER = lib.TPM2_PS_SERVER
    PERIPHERAL = lib.TPM2_PS_PERIPHERAL
    TSS = lib.TPM2_PS_TSS
    STORAGE = lib.TPM2_PS_STORAGE
    AUTHENTICATION = lib.TPM2_PS_AUTHENTICATION
    EMBEDDED = lib.TPM2_PS_EMBEDDED
    HARDCOPY = lib.TPM2_PS_HARDCOPY
    INFRASTRUCTURE = lib.TPM2_PS_INFRASTRUCTURE
    VIRTUALIZATION = lib.TPM2_PS_VIRTUALIZATION
    TNC = lib.TPM2_PS_TNC
    MULTI_TENANT = lib.TPM2_PS_MULTI_TENANT
    TC = lib.TPM2_PS_TC

class TPM2_HT(int):
    PCR = lib.TPM2_HT_PCR
    NV_INDEX = lib.TPM2_HT_NV_INDEX
    HMAC_SESSION = lib.TPM2_HT_HMAC_SESSION
    LOADED_SESSION = lib.TPM2_HT_LOADED_SESSION
    POLICY_SESSION = lib.TPM2_HT_POLICY_SESSION
    SAVED_SESSION = lib.TPM2_HT_SAVED_SESSION
    PERMANENT = lib.TPM2_HT_PERMANENT
    TRANSIENT = lib.TPM2_HT_TRANSIENT
    PERSISTENT = lib.TPM2_HT_PERSISTENT

class TPMA_SESSION(int):
    CONTINUESESSION = lib.TPMA_SESSION_CONTINUESESSION
    AUDITEXCLUSIVE = lib.TPMA_SESSION_AUDITEXCLUSIVE
    AUDITRESET = lib.TPMA_SESSION_AUDITRESET
    DECRYPT = lib.TPMA_SESSION_DECRYPT
    ENCRYPT = lib.TPMA_SESSION_ENCRYPT
    AUDIT = lib.TPMA_SESSION_AUDIT

class TPMA_LOCALITY(int):
    ZERO = lib.TPMA_LOCALITY_TPM2_LOC_ZERO
    ONE = lib.TPMA_LOCALITY_TPM2_LOC_ONE
    TWO = lib.TPMA_LOCALITY_TPM2_LOC_TWO
    THREE = lib.TPMA_LOCALITY_TPM2_LOC_THREE
    FOUR = lib.TPMA_LOCALITY_TPM2_LOC_FOUR
    EXTENDED_MASK = lib.TPMA_LOCALITY_EXTENDED_MASK
    EXTENDED_SHIFT = lib.TPMA_LOCALITY_EXTENDED_SHIFT

class TPM2_NT(int):
    ORDINARY = lib.TPM2_NT_ORDINARY
    COUNTER = lib.TPM2_NT_COUNTER
    BITS = lib.TPM2_NT_BITS
    EXTEND = lib.TPM2_NT_EXTEND
    PIN_FAIL = lib.TPM2_NT_PIN_FAIL
    PIN_PASS = lib.TPM2_NT_PIN_PASS

class TPM2_HR(int):
    HANDLE_MASK = lib.TPM2_HR_HANDLE_MASK
    RANGE_MASK = lib.TPM2_HR_RANGE_MASK
    SHIFT = lib.TPM2_HR_SHIFT
    PCR = lib.TPM2_HR_PCR
    HMAC_SESSION = lib.TPM2_HR_HMAC_SESSION
    POLICY_SESSION = lib.TPM2_HR_POLICY_SESSION
    TRANSIENT = lib.TPM2_HR_TRANSIENT
    PERSISTENT = lib.TPM2_HR_PERSISTENT
    NV_INDEX = lib.TPM2_HR_NV_INDEX
    PERMANENT = lib.TPM2_HR_PERMANENT

class TPM2_HC(int):
    HR_HANDLE_MASK = lib.TPM2_HR_HANDLE_MASK
    HR_RANGE_MASK = lib.TPM2_HR_RANGE_MASK
    HR_SHIFT = lib.TPM2_HR_SHIFT
    HR_PCR = lib.TPM2_HR_PCR
    HR_HMAC_SESSION = lib.TPM2_HR_HMAC_SESSION
    HR_POLICY_SESSION = lib.TPM2_HR_POLICY_SESSION
    HR_TRANSIENT = lib.TPM2_HR_TRANSIENT
    HR_PERSISTENT = lib.TPM2_HR_PERSISTENT
    HR_NV_INDEX = lib.TPM2_HR_NV_INDEX
    HR_PERMANENT = lib.TPM2_HR_PERMANENT
    PCR_FIRST = lib.TPM2_PCR_FIRST
    PCR_LAST = lib.TPM2_PCR_LAST
    HMAC_SESSION_FIRST = lib.TPM2_HMAC_SESSION_FIRST
    HMAC_SESSION_LAST = lib.TPM2_HMAC_SESSION_LAST
    LOADED_SESSION_FIRST = lib.TPM2_LOADED_SESSION_FIRST
    LOADED_SESSION_LAST = lib.TPM2_LOADED_SESSION_LAST
    POLICY_SESSION_FIRST = lib.TPM2_POLICY_SESSION_FIRST
    POLICY_SESSION_LAST = lib.TPM2_POLICY_SESSION_LAST
    TRANSIENT_FIRST = lib.TPM2_TRANSIENT_FIRST
    ACTIVE_SESSION_FIRST = lib.TPM2_ACTIVE_SESSION_FIRST
    ACTIVE_SESSION_LAST = lib.TPM2_ACTIVE_SESSION_LAST
    TRANSIENT_LAST = lib.TPM2_TRANSIENT_LAST
    PERSISTENT_FIRST = lib.TPM2_PERSISTENT_FIRST
    PERSISTENT_LAST = lib.TPM2_PERSISTENT_LAST
    PLATFORM_PERSISTENT = lib.TPM2_PLATFORM_PERSISTENT
    NV_INDEX_FIRST = lib.TPM2_NV_INDEX_FIRST
    NV_INDEX_LAST = lib.TPM2_NV_INDEX_LAST
    PERMANENT_FIRST = lib.TPM2_PERMANENT_FIRST
    PERMANENT_LAST = lib.TPM2_PERMANENT_LAST

class TPM2_CLOCK(int):
    COARSE_SLOWER = lib.TPM2_CLOCK_COARSE_SLOWER
    MEDIUM_SLOWER = lib.TPM2_CLOCK_MEDIUM_SLOWER
    FINE_SLOWER = lib.TPM2_CLOCK_FINE_SLOWER
    NO_CHANGE = lib.TPM2_CLOCK_NO_CHANGE
    FINE_FASTER = lib.TPM2_CLOCK_FINE_FASTER
    MEDIUM_FASTER = lib.TPM2_CLOCK_MEDIUM_FASTER
    COARSE_FASTER = lib.TPM2_CLOCK_COARSE_FASTER
TPM2_CLOCK_ADJUST = TPM2_CLOCK

class TPMA_NV(int):
    PPWRITE = lib.TPMA_NV_PPWRITE
    OWNERWRITE = lib.TPMA_NV_OWNERWRITE
    AUTHWRITE = lib.TPMA_NV_AUTHWRITE
    POLICYWRITE = lib.TPMA_NV_POLICYWRITE
    TPM2_NT_MASK = lib.TPMA_NV_TPM2_NT_MASK
    TPM2_NT_SHIFT = lib.TPMA_NV_TPM2_NT_SHIFT
    POLICY_DELETE = lib.TPMA_NV_POLICY_DELETE
    WRITELOCKED = lib.TPMA_NV_WRITELOCKED
    WRITEALL = lib.TPMA_NV_WRITEALL
    WRITEDEFINE = lib.TPMA_NV_WRITEDEFINE
    WRITE_STCLEAR = lib.TPMA_NV_WRITE_STCLEAR
    GLOBALLOCK = lib.TPMA_NV_GLOBALLOCK
    PPREAD = lib.TPMA_NV_PPREAD
    OWNERREAD = lib.TPMA_NV_OWNERREAD
    AUTHREAD = lib.TPMA_NV_AUTHREAD
    POLICYREAD = lib.TPMA_NV_POLICYREAD
    NO_DA = lib.TPMA_NV_NO_DA
    ORDERLY = lib.TPMA_NV_ORDERLY
    CLEAR_STCLEAR = lib.TPMA_NV_CLEAR_STCLEAR
    READLOCKED = lib.TPMA_NV_READLOCKED
    WRITTEN = lib.TPMA_NV_WRITTEN
    PLATFORMCREATE = lib.TPMA_NV_PLATFORMCREATE
    READ_STCLEAR = lib.TPMA_NV_READ_STCLEAR

class TPMA_CC(int):
    COMMANDINDEX_MASK = lib.TPMA_CC_COMMANDINDEX_MASK
    COMMANDINDEX_SHIFT = lib.TPMA_CC_COMMANDINDEX_SHIFT
    NV = lib.TPMA_CC_NV
    EXTENSIVE = lib.TPMA_CC_EXTENSIVE
    FLUSHED = lib.TPMA_CC_FLUSHED
    CHANDLES_MASK = lib.TPMA_CC_CHANDLES_MASK
    CHANDLES_SHIFT = lib.TPMA_CC_CHANDLES_SHIFT
    RHANDLE = lib.TPMA_CC_RHANDLE
    V = lib.TPMA_CC_V
    RES_MASK = lib.TPMA_CC_RES_MASK
    RES_SHIFT = lib.TPMA_CC_RES_SHIFT

class TPMA_OBJECT(int):
    FIXEDTPM = lib.TPMA_OBJECT_FIXEDTPM
    STCLEAR = lib.TPMA_OBJECT_STCLEAR
    FIXEDPARENT = lib.TPMA_OBJECT_FIXEDPARENT
    SENSITIVEDATAORIGIN = lib.TPMA_OBJECT_SENSITIVEDATAORIGIN
    USERWITHAUTH = lib.TPMA_OBJECT_USERWITHAUTH
    ADMINWITHPOLICY = lib.TPMA_OBJECT_ADMINWITHPOLICY
    NODA = lib.TPMA_OBJECT_NODA
    ENCRYPTEDDUPLICATION = lib.TPMA_OBJECT_ENCRYPTEDDUPLICATION
    RESTRICTED = lib.TPMA_OBJECT_RESTRICTED
    DECRYPT = lib.TPMA_OBJECT_DECRYPT
    SIGN_ENCRYPT = lib.TPMA_OBJECT_SIGN_ENCRYPT

class TPMA_ALGORITHM(int):
    ASYMMETRIC = lib.TPMA_ALGORITHM_ASYMMETRIC
    SYMMETRIC = lib.TPMA_ALGORITHM_SYMMETRIC
    HASH = lib.TPMA_ALGORITHM_HASH
    OBJECT = lib.TPMA_ALGORITHM_OBJECT
    SIGNING = lib.TPMA_ALGORITHM_SIGNING
    ENCRYPTING = lib.TPMA_ALGORITHM_ENCRYPTING
    METHOD = lib.TPMA_ALGORITHM_METHOD

class TPMA_PERMANENT(int):
    OWNERAUTHSET = lib.TPMA_PERMANENT_OWNERAUTHSET
    ENDORSEMENTAUTHSET = lib.TPMA_PERMANENT_ENDORSEMENTAUTHSET
    LOCKOUTAUTHSET = lib.TPMA_PERMANENT_LOCKOUTAUTHSET
    DISABLECLEAR = lib.TPMA_PERMANENT_DISABLECLEAR
    INLOCKOUT = lib.TPMA_PERMANENT_INLOCKOUT
    TPMGENERATEDEPS = lib.TPMA_PERMANENT_TPMGENERATEDEPS

class TPMA_STARTUP(int):
    CLEAR_PHENABLE = lib.TPMA_STARTUP_CLEAR_PHENABLE
    CLEAR_SHENABLE = lib.TPMA_STARTUP_CLEAR_SHENABLE
    CLEAR_EHENABLE = lib.TPMA_STARTUP_CLEAR_EHENABLE
    CLEAR_PHENABLENV = lib.TPMA_STARTUP_CLEAR_PHENABLENV
    CLEAR_ORDERLY = lib.TPMA_STARTUP_CLEAR_ORDERLY

class TPMA_MEMORY(int):
    SHAREDRAM = lib.TPMA_MEMORY_SHAREDRAM
    SHAREDNV = lib.TPMA_MEMORY_SHAREDNV
    OBJECTCOPIEDTORAM = lib.TPMA_MEMORY_OBJECTCOPIEDTORAM

### handy contructors

def TPM2B_ATTEST():
    return ffi.new('TPM2B_ATTEST *')

def TPM2B_CONTEXT_DATA():
    return ffi.new('TPM2B_CONTEXT_DATA *')

def TPM2B_CONTEXT_SENSITIVE():
    return ffi.new('TPM2B_CONTEXT_SENSITIVE *')

def TPM2B_CREATION_DATA():
    return ffi.new('TPM2B_CREATION_DATA *')

def TPM2B_DATA():
    return ffi.new('TPM2B_DATA *')

def TPM2B_DIGEST():
    return ffi.new('TPM2B_DIGEST *')

def TPM2B_ECC_PARAMETER():
    return ffi.new('TPM2B_ECC_PARAMETER *')

def TPM2B_ECC_POINT():
    return ffi.new('TPM2B_ECC_POINT *')

def TPM2B_ENCRYPTED_SECRET():
    return ffi.new('TPM2B_ENCRYPTED_SECRET *')

def TPM2B_EVENT():
    return ffi.new('TPM2B_EVENT *')

def TPM2B_ID_OBJECT():
    return ffi.new('TPM2B_ID_OBJECT *')

def TPM2B_IV():
    return ffi.new('TPM2B_IV *')

def TPM2B_MAX_BUFFER():
    return ffi.new('TPM2B_MAX_BUFFER *')

def TPM2B_MAX_NV_BUFFER():
    return ffi.new('TPM2B_MAX_NV_BUFFER *')

def TPM2B_NAME():
    return ffi.new('TPM2B_NAME *')

def TPM2B_NV_PUBLIC():
    return ffi.new('TPM2B_NV_PUBLIC *')

def TPM2B_PRIVATE():
    return ffi.new('TPM2B_PRIVATE *')

def TPM2B_PRIVATE_KEY_RSA():
    return ffi.new('TPM2B_PRIVATE_KEY_RSA *')

def TPM2B_PRIVATE_VENDOR_SPECIFIC():
    return ffi.new('TPM2B_PRIVATE_VENDOR_SPECIFIC *')

def TPM2B_PUBLIC():
    return ffi.new('TPM2B_PUBLIC *')

def TPM2B_PUBLIC_KEY_RSA():
    return ffi.new('TPM2B_PUBLIC_KEY_RSA *')

def TPM2B_SENSITIVE():
    return ffi.new('TPM2B_SENSITIVE *')

def TPM2B_SENSITIVE_CREATE():
    return ffi.new('TPM2B_SENSITIVE_CREATE *')

def TPM2B_SENSITIVE_DATA():
    return ffi.new('TPM2B_SENSITIVE_DATA *')

def TPM2B_SYM_KEY():
    return ffi.new('TPM2B_SYM_KEY *')

def TPM2B_TEMPLATE():
    return ffi.new('TPM2B_TEMPLATE *')

def TPML_AC_CAPABILITIES():
    return ffi.new('TPML_AC_CAPABILITIES *')

def TPML_ALG():
    return ffi.new('TPML_ALG *')

def TPML_ALG_PROPERTY():
    return ffi.new('TPML_ALG_PROPERTY *')

def TPML_CC():
    return ffi.new('TPML_CC *')

def TPML_CCA():
    return ffi.new('TPML_CCA *')

def TPML_DIGEST():
    return ffi.new('TPML_DIGEST *')

def TPML_DIGEST_VALUES():
    return ffi.new('TPML_DIGEST_VALUES *')

def TPML_ECC_CURVE():
    return ffi.new('TPML_ECC_CURVE *')

def TPML_HANDLE():
    return ffi.new('TPML_HANDLE *')

def TPML_INTEL_PTT_PROPERTY():
    return ffi.new('TPML_INTEL_PTT_PROPERTY *')

def TPML_PCR_SELECTION():
    return ffi.new('TPML_PCR_SELECTION *')

def TPML_TAGGED_PCR_PROPERTY():
    return ffi.new('TPML_TAGGED_PCR_PROPERTY *')

def TPML_TAGGED_TPM_PROPERTY():
    return ffi.new('TPML_TAGGED_TPM_PROPERTY *')

def TPMS_AC_OUTPUT():
    return ffi.new('TPMS_AC_OUTPUT *')

def TPMS_ALGORITHM_DESCRIPTION():
    return ffi.new('TPMS_ALGORITHM_DESCRIPTION *')

def TPMS_ALGORITHM_DETAIL_ECC():
    return ffi.new('TPMS_ALGORITHM_DETAIL_ECC *')

def TPMS_ALG_PROPERTY():
    return ffi.new('TPMS_ALG_PROPERTY *')

def TPMS_ASYM_PARMS():
    return ffi.new('TPMS_ASYM_PARMS *')

def TPMS_ATTEST():
    return ffi.new('TPMS_ATTEST *')

def TPMS_AUTH_COMMAND():
    return ffi.new('TPMS_AUTH_COMMAND *')

def TPMS_AUTH_RESPONSE():
    return ffi.new('TPMS_AUTH_RESPONSE *')

def TPMS_CAPABILITY_DATA():
    return ffi.new('TPMS_CAPABILITY_DATA *')

def TPMS_CERTIFY_INFO():
    return ffi.new('TPMS_CERTIFY_INFO *')

def TPMS_CLOCK_INFO():
    return ffi.new('TPMS_CLOCK_INFO *')

def TPMS_COMMAND_AUDIT_INFO():
    return ffi.new('TPMS_COMMAND_AUDIT_INFO *')

def TPMS_CONTEXT():
    return ffi.new('TPMS_CONTEXT *')

def TPMS_CONTEXT_DATA():
    return ffi.new('TPMS_CONTEXT_DATA *')

def TPMS_CREATION_DATA():
    return ffi.new('TPMS_CREATION_DATA *')

def TPMS_CREATION_INFO():
    return ffi.new('TPMS_CREATION_INFO *')

def TPMS_ECC_PARMS():
    return ffi.new('TPMS_ECC_PARMS *')

def TPMS_ECC_POINT():
    return ffi.new('TPMS_ECC_POINT *')

def TPMS_EMPTY():
    return ffi.new('TPMS_EMPTY *')

def TPMS_ID_OBJECT():
    return ffi.new('TPMS_ID_OBJECT *')

def TPMS_KEYEDHASH_PARMS():
    return ffi.new('TPMS_KEYEDHASH_PARMS *')

def TPMS_NV_CERTIFY_INFO():
    return ffi.new('TPMS_NV_CERTIFY_INFO *')

def TPMS_NV_PIN_COUNTER_PARAMETERS():
    return ffi.new('TPMS_NV_PIN_COUNTER_PARAMETERS *')

def TPMS_NV_PUBLIC():
    return ffi.new('TPMS_NV_PUBLIC *')

def TPMS_PCR_SELECT():
    return ffi.new('TPMS_PCR_SELECT *')

def TPMS_PCR_SELECTION():
    return ffi.new('TPMS_PCR_SELECTION *')

def TPMS_QUOTE_INFO():
    return ffi.new('TPMS_QUOTE_INFO *')

def TPMS_RSA_PARMS():
    return ffi.new('TPMS_RSA_PARMS *')

def TPMS_SCHEME_ECDAA():
    return ffi.new('TPMS_SCHEME_ECDAA *')

def TPMS_SCHEME_HASH():
    return ffi.new('TPMS_SCHEME_HASH *')

def TPMS_SCHEME_XOR():
    return ffi.new('TPMS_SCHEME_XOR *')

def TPMS_SENSITIVE_CREATE():
    return ffi.new('TPMS_SENSITIVE_CREATE *')

def TPMS_SESSION_AUDIT_INFO():
    return ffi.new('TPMS_SESSION_AUDIT_INFO *')

def TPMS_SIGNATURE_ECC():
    return ffi.new('TPMS_SIGNATURE_ECC *')

def TPMS_SIGNATURE_RSA():
    return ffi.new('TPMS_SIGNATURE_RSA *')

def TPMS_SYMCIPHER_PARMS():
    return ffi.new('TPMS_SYMCIPHER_PARMS *')

def TPMS_TAGGED_PCR_SELECT():
    return ffi.new('TPMS_TAGGED_PCR_SELECT *')

def TPMS_TAGGED_PROPERTY():
    return ffi.new('TPMS_TAGGED_PROPERTY *')

def TPMS_TIME_ATTEST_INFO():
    return ffi.new('TPMS_TIME_ATTEST_INFO *')

def TPMS_TIME_INFO():
    return ffi.new('TPMS_TIME_INFO *')

