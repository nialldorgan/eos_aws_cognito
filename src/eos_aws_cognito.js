import {EosCognitoUser, UserPool, UserAuthenticationData, User, EosPoolData} from './eos_aws_cognitoIdentity.js';
import errors from './errors.js';
import status from './status.js';
import defs from './defs.js';

class EosAwsCognito {

    //EosPoolData is an instance of the EosPoolData class

    constructor(EosPoolData)
    {
        this.poolData = EosPoolData;
    }

    //call this function to login a user, the detauls supplied as User will need to be username and password
    //the User is an instance of the User class

    /////////////////////////////////////////////////////////////////////////////////////////////////////////
    // Login and out
    /////////////////////////////////////////////////////////////////////////////////////////////////////////

    login(User)
    {
        const authDetails = new UserAuthenticationData(User.username, User.password);
        const userPool = new UserPool(this.poolData);
        const cognitoUser = new EosCognitoUser(User.username, userPool);
        return this.basicLogin(authDetails, cognitoUser);        
    }

    customLogin(User)
    {
        const authDetails = new UserAuthenticationData(User.username, User.password);
        const userPool = new UserPool(this.poolData);
        const cognitoUser = new EosCognitoUser(User.username, userPool);
        cognitoUser.setAuthenticationFlowType('CUSTOM_AUTH');
        return new Promise((resolve, reject) => {
            cognitoUser.initiateAuth(authDetails, {
                onSuccess: (result) => {
                    resolve({status: status.login_succeeded, data:result});
                },
                onFailure: (err) => {
                    reject({status: errors.login_failed, data:err});
                },
                customChallenge: (challengeParameters) => {
                    resolve({status: status.customChallenge, data:{cognitoUser: cognitoUser, parameters:challengeParameters}});
                },
            });
        });
    }

    sendCustomChallengeResponse(challengeResponses, cognitoUser, clientMetadata = null)
    {
        return new Promise((resolve, reject) => {
            cognitoUser.sendCustomChallengeAnswer(challengeResponses, {
                onSuccess: (success) => {
                    resolve(success);
                },
                onFailure: (error) => {
                    reject(error);
                }
            }, clientMetadata);
        });
    }

    simpleUsernamePasswordLogin(User)
    {
        const authDetails = new UserAuthenticationData(User.username, User.password);
        const userPool = new UserPool(this.poolData);
        const cognitoUser = new EosCognitoUser(User.username, userPool);
        cognitoUser.setAuthenticationFlowType('USER_PASSWORD_AUTH');
        return this.basicLogin(authDetails, cognitoUser);
    }

    //call this to logout the current user

    logout(global = false){
        const cognitoUser = this.getCurrentUser();
        if(!cognitoUser)
            throw errors.no_user_logged_in;
        if (global) {
            return this.getCognitoUser()
            .then((cogUser) => {
                return new Promise((resolve, reject) => {
                    cogUser.globalSignOut({
                        onSuccess: (success) => {
                            resolve(success);
                        },
                        onFailure: (error) => {
                            reject(error);
                        } 
                    })
                })
            })                
        } else {
            cognitoUser.signOut();
            return true;
        }        
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    // Refresh token
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    requestNewIdToken(clientMetadata = null)
    {
        return this.getCurrentSession()
        .then((session) => {  
            var refresh_token = session.session.getRefreshToken();
            return new Promise((resolve, reject) => {
                session.cognitoUser.refreshSession(refresh_token, (error, success) => {
                    if(error)
                        reject(error);
                    resolve(success);
                });
            })
        });
    }

    /////////////////////////////////////////////////////////////////////////////////////////////////////
    // register a new user
    /////////////////////////////////////////////////////////////////////////////////////////////////////

    //call this to register a new user
    //the details collected and supplied as User will depend on the requirements of the UserPool
    registerNewUser(User, validationData = [], clientMetadata = null)
    {
        const userPool = new UserPool(this.poolData);
        return new Promise((resolve, reject) => {
            userPool.signUp(User.username, User.password, User.attributeList, validationData, (error, result) => {
                if(error)
                    reject(error);
                resolve(result);
            }, clientMetadata);
        });        
    }

    //call this to return the confirmation code sent to the user on registration
    confirmRegistrationCode(User, code, ForceAliasCreation = false, clientMetadata = null)
    {
        const userPool = new UserPool(this.poolData);
        const cognitoUser = new EosCognitoUser(User.username, userPool);
        return new Promise((resolve, reject) => {
            cognitoUser.confirmRegistration(code, ForceAliasCreation, (error, success) => {
                if(error)
                    reject(error);
                resolve(success);
            }, clientMetadata);
        })
    }

    resendNewUserConfirmationCode(User, clientMetadata = null)
    {
        const userPool = new UserPool(this.poolData);
        const cognitoUser = new EosCognitoUser(User.username, userPool);
        return new Promise((resolve, reject) => {
            cognitoUser.resendConfirmationCode((error, success) => {
                if(error)
                    reject(error);
                resolve(success);
            }, clientMetadata);
        })
    }    

    ////////////////////////////////////////////////////////////////////////////////////////////////////////
    // user attributes
    ////////////////////////////////////////////////////////////////////////////////////////////////////////
    

    //call this function to get the current signed in users attributes.

    getCurrentUserAttributes()
    {
        return this.getCognitoUser()
        .then((cognitoUser) => {            
            return new Promise((resolve, reject) => {
                cognitoUser.getUserAttributes((err, attributes) => {
                    if(err)
                        reject(err)
                    resolve(attributes);
                })
            });
        })
        .catch(error => {
            return new Promise((resolve, reject) => {
                reject(error);
            });
        })
    }

    requestUserAttributeVerificationCode(attributeName, clientMetadata = null)
    {
        return this.getCognitoUser()
        .then((cognitoUser) => {  
            return new Promise((resolve, reject) => {
                cognitoUser.getAttributeVerificationCode(attributeName, {
                    onSuccess: () => { resolve('success'); },
                    onFailure: (error) => { reject(error); },
                    inputVerificationCode: (result) => { resolve(result); }
                }, clientMetadata);
            });
        });   
    }

    verifyUserAttribute(attributeName, code, clientMetadata = null)
    {
        return this.getCognitoUser()
        .then((cognitoUser) => {  
            return new Promise((resolve, reject) => {
                cognitoUser.verifyAttribute(attributeName, code, {
                    onSuccess: (result) => { resolve(result); },
                    onFailure: (error) => { reject(error); }
                }, clientMetadata);
            });
        });    
    }

    //takes an array of attribute name(s)
    deleteUserAttributes(attributeList)
    {
        return this.getCognitoUser()
        .then((cognitoUser) => {  
            return new Promise((resolve, reject) => {
                cognitoUser.deleteAttributes(attributeList, (error, success) => {
                    if(error)
                        reject(error);
                    resolve(success);
                });
            });
        }); 
    }

    //takes an array of CognitoUserAttributes
    updateUserAttributes(attributeList, clientMetadata = null)
    {
        return this.getCognitoUser()
        .then((cognitoUser) => {  
            return new Promise((resolve, reject) => {
                cognitoUser.updateAttributes(attributeList, (error, success) => {
                    if(error)
                        reject(error);
                    resolve(success);
                }, clientMetadata);
            });
        }); 
    }

    getUserData()
    {
        return this.getCognitoUser()
        .then((cognitoUser) => {  
            return new Promise((resolve, reject) => {
                cognitoUser.getUserData((error, userData) => {
                    if(error)
                        reject(error);
                    resolve(userData);
                });
            });
        }); 
    }

    //////////////////////////////////////////////////////////////////////////////////////////////////////////
    // delete a user
    //////////////////////////////////////////////////////////////////////////////////////////////////////////

    //call this function to allow an authenticated user to delete their account
    removeUserAccount(User, clientMetadata = null)
    {
        return this.getCognitoUser()
        .then((cognitoUser) => {  
            return new Promise((resolve, reject) => {
                cognitoUser.deleteUser((error, success) => {
                    if(error)
                        reject(error);
                    resolve(success);
                }, clientMetadata);
            });
        });
    }

    //////////////////////////////////////////////////////////////////////////////////////////////////////////
    //user devices
    //////////////////////////////////////////////////////////////////////////////////////////////////////////

    // There are 3 option settings on congnito for devices
    // 1. Tracking disabled
    // 2. Tracking on remembering devices optional client needs to opt in
    // 3. Tracking on devices remembered automatically

    // if option 1 is used the following functions have no effect
    // If option 2 then devices will be tracked however listCurrentUserDevices will return an empty set unless the user opts to remember their device first
    // If option 3 listCurrentUserDevices will return a list of all devices the user has logged in with, devices can be exclued or included again using 
    // forgetCurrentDevice or rememberCurrentDevice
    // displayCurrentDeviceInformation will work in with option 3 and option 2 when rememberCurrentDevice has been called first

    //remember the users current device
    rememberCurrentDevice()
    {
        return this.getCognitoUser()
        .then((cognitoUser) => { 
            return new Promise((resolve, reject) => {
                cognitoUser.getCachedDeviceKeyAndPassword(); //call this function before calls to access devices as otherwise this.deviceKey is undefined
                cognitoUser.setDeviceStatusRemembered({
                    onSuccess: (result) => { resolve(result); },
                    onFailure: (error) => { reject(error); }
                });
            });
        });
    }

    forgetCurrentDevice()
    {
        return this.getCognitoUser()
        .then((cognitoUser) => { 
            return new Promise((resolve, reject) => {
                cognitoUser.getCachedDeviceKeyAndPassword();
                cognitoUser.setDeviceStatusNotRemembered({
                    onSuccess: (result) => { resolve(result); },
                    onFailure: (error) => { reject(error); }
                });
            });
        });
    }

    //List information about the current device.
    displayCurrentDeviceInformation(){
        return this.getCognitoUser()
        .then((cognitoUser) => { 
            return new Promise((resolve, reject) => {
                cognitoUser.getCachedDeviceKeyAndPassword();
                cognitoUser.getDevice({
                    onSuccess: (result) => { resolve(result); },
                    onFailure: (error) => { reject(error); }
                });
            });
        });
    }

    listCurrentUserDevices(limit = 5, paginationToken = null)
    {
        return this.getCognitoUser()
        .then((cognitoUser) => { 
            return new Promise((resolve, reject) => {
                cognitoUser.listDevices(limit, paginationToken, {
                    onSuccess: (result) => { resolve(result); },
                    onFailure: (error) => { reject(error); }
                });
            });
        });
    }

    ///////////////////////////////////////////////////////////////////////////////////////////////////////////
    // MFA
    ///////////////////////////////////////////////////////////////////////////////////////////////////////////

    //the first stage in setting up software MFA call this function first
    //it will return a secret key which can be used to generate a TOTP using a TOTP generator device or function
    //you can also use the returned secret key to generate a QR code for users to set up their TOTP device
    //After calling this function you need to call verifyNewTotpCode so the user can test and verify that their device is generating the
    //necessary codes correctly before calling setMfaPreferences which will enable MFA for the user.

    getUserMfaOptions()
    {
        return this.getCognitoUser()
        .then((cognitoUser) => {  
            return new Promise((resolve, reject) => {
                cognitoUser.getMFAOptions((error, mfaOptions) => {
                    if(error)
                        reject(error);
                    resolve(mfaOptions);
                });
            });
        }); 
    }

    requestSoftwareMfaSetup()
    {
        return this.getCognitoUser()
        .then((cognitoUser) => {
            return new Promise((resolve, reject) => {
                cognitoUser.associateSoftwareToken({
                    onFailure: (error) => {
                        reject(error);
                    },
                    associateSecretCode: (data) => {
                        resolve({status: 'associateSecretCode', code: data});
                    }
                });
            }); 
        })
        .catch(error => {
            return new Promise((resolve, reject) => {
                reject(error);
            });
        })
    }

    //the second stage in setting up Software MFA, call this function to verify the new TOTP code set up following a call to requestSoftwareMfaSetup
    //a TOTP device is required to generate the necessary code, device_name can be any string to identify the given device

    verifyNewTotpCode(code, device_name)
    {
        return this.getCognitoUser()
        .then((cognitoUser) => {
            return new Promise((resolve, reject) => {
                cognitoUser.verifySoftwareToken(code, device_name, {
                    onFailure: (error) => {
                        reject(error);
                    },
                    onSuccess: (success) => {
                        resolve({status: 'success', data: success});
                    }
                });
            })
        })
        .catch(error => {
            return new Promise((resolve, reject) => {
                reject(error);
            });
        })
    }

    //the last stage in setting up MFA, call this function after calling requestSoftwareMfaSetup followed by verifyNewTotpCode if using Software MFA
    //call this without any other functions if using SMS MFA.
    //NB calling this for SMS MFA if the user pool is not set up for MFA or if the user has no mobile phone number listed will cause the user to be
    //unable to login, need to call admin-set-user-mfa-preference using the aws cli to turn off SMS MFA for this user if so.

    setMfaPreferences(mfaType, enable = true)
    {        
        return this.getCognitoUser()
        .then((cognitoUser) => {
            return new Promise((resolve, reject) => {
                cognitoUser.setUserMfaPreference(this.setMfaType('SMS', defs.mfaTypes[mfaType], enable), 
                    this.setMfaType('TOTP', defs.mfaTypes[mfaType], enable), (error, result) => {
                    if(error)
                        reject(error);
                    resolve(result);
                })
            });
        })
        .catch(error => {
            return new Promise((resolve, reject) => {
                reject(error);
            });
        })
    }

    //sends the MFA code, given by the current cognitoUser
    //the code is supplied by the user attempting login
    //the cognitoUser is returned by the login function when MFA is required
    //type needs to be SMS_MFA or SOFTWARE_TOKEN_MFA
    //the type required is returned as the result from the login function
    sendMfaCode(code, cognitoUser, type, clientMetadata = null)
    {
        return new Promise((resolve, reject) => {
            cognitoUser.sendMFACode(code, {
                onSuccess: (success) => {
                    resolve(success);
                },
                onFailure: (error) => {
                    reject(error);
                }
            }, type, clientMetadata);
        })
        .catch(error => {
            return new Promise((resolve, reject) => {
                reject(error);
            });
        })
    }


    //////////////////////////////////////////////////////////////////////////////////////////////////
    // Passwords
    /////////////////////////////////////////////////////////////////////////////////////////////////

    //allow an authenticated user to change their password
    changeUserPassword(User, oldPassword, newPassword, clientMetadata = null)
    {
        return this.getCognitoUser()
        .then((cognitoUser) => {
            return new Promise((resolve, reject) => {
                cognitoUser.changePassword(oldPassword, newPassword, (error, result) => {
                    if(error)
                        reject(error);
                    resolve(result);
                }, clientMetadata)
            });
        });
    }

    //allow the user to request a password reset code to be sent to their email address
    requestUserPasswordReset(User, clientMetadata = null)
    {
        const userPool = new UserPool(this.poolData);
        const cognitoUser = new EosCognitoUser(User.username, userPool);
        return new Promise((resolve, reject) => {
            cognitoUser.forgotPassword({
                onSuccess: (data) => { resolve (data); },
                onFailure: (error) => { reject(error); },
                onInputVerification: (data) => { resolve(data); }
            }, clientMetadata);
        });        
    }

    //allow a user to reset their password using the password verification code sent after a call to requestUserPasswordReset
    resetUserPassword(User, code, newPassword, clientMetadata = null)
    {
        const userPool = new UserPool(this.poolData);
        const cognitoUser = new EosCognitoUser(User.username, userPool);
        return new Promise((resolve, reject) => {
            cognitoUser.confirmPassword(code, newPassword, {
                onSuccess: (data) => { resolve (data); },
                onFailure: (error) => { reject(error); },                
            }, clientMetadata);
        });
    }

    completePasswordChallenge(cognitoUser, newpassword, userAttributes, clientMetadata = null)
    {
        return new Promise((resolve, reject) => {
            cognitoUser.completeNewPasswordChallenge(newpassword, userAttributes, {
                onSuccess: (success) => {
                    resolve(success);
                },
                onFailure: (error) => {
                    reject(error);
                }
            }, clientMetadata)
        });
    }


    //////////////////////////////////////////////////////////////////////////////////////////////////
    // Private Functions, do not call these directly
    //////////////////////////////////////////////////////////////////////////////////////////////////

    basicLogin(authDetails, cognitoUser)
    {
        return new Promise((resolve, reject) => {
            cognitoUser.authenticateUser(authDetails, {
                onSuccess: (result) => {
                    resolve({status: status.login_succeeded, data:result});
                },
                onFailure: (err) => {
                    reject({status: errors.login_failed, data:err});
                },
                mfaRequired: (codeDeliveryDetails) => {
                    resolve({status: status.sms_mfa, data: {cognitoUser: cognitoUser, result: codeDeliveryDetails}})
                },

                totpRequired: (secretCode) => {
                    resolve({status: status.totp_required, data: {cognitoUser: cognitoUser, result: secretCode}})
                },

                newPasswordRequired: (userAttributes, requiredAttributes) => {
                    delete userAttributes.email_verified;
                    resolve({status: status.newPassword, data: {cognitoUser: cognitoUser, result: {userAttributes: userAttributes, requiredAttributes: requiredAttributes}}})
                }
            })
        });
    }

    //gets an instance of a new Userpool user (not signed in)
    getCurrentUser(){
        const userPool = new UserPool(this.poolData);
        return userPool.getCurrentUser();
    }

    //gets the current signed in user error if no signed in user
    getCognitoUser()
    {
        return this.getCurrentSession()
        .then((session) => {
            return new Promise((resolve, reject) => {
                resolve(session.cognitoUser);
            });
        })
        .catch(error => {
            return new Promise((resolve, reject) => {
                reject(error);
            });
        })
    }

    //returns the current session, error if no signed in user
    getCurrentSession()
    {
        const cognitoUser = this.getCurrentUser();
        if(!cognitoUser)
            return new Promise((resolve, reject) => {
                reject(errors.no_current_user);
            });
        return new Promise((resolve, reject) => {
            cognitoUser.getSession((err, success) => {
                if(err)
                    reject(err);
                resolve({cognitoUser: cognitoUser, session: success});
            })
        })
    }

    //utility function to set the MFA preference object for either software or SMS
    setMfaType(type, requested, enable = true)
    {
        if(enable)
            return requested === 'SMS_MFA' && type === 'SMS'? defs.enableMfaSettings: requested === 'SOFTWARE_TOKEN_MFA' && type === 'TOTP'? defs.enableMfaSettings: null;
        return requested === 'SMS_MFA' && type === 'SMS'? defs.disableMfaSettings: requested === 'SOFTWARE_TOKEN_MFA' && type === 'TOTP'? defs.disableMfaSettings: null;
    }


}

export {EosAwsCognito, EosPoolData, User};
export default {EosAwsCognito, EosPoolData, User};