import { CognitoIdentityClient } from "@aws-sdk/client-cognito-identity";
import {fromCognitoIdentityPool} from "@aws-sdk/credential-provider-cognito-identity";
import { 
    CognitoIdentityProviderClient,  
    ListUsersCommand,
    ListGroupsCommand,
    AdminGetUserCommand,   
    AdminCreateUserCommand, 
    AdminDisableUserCommand,
    AdminEnableUserCommand,
    AdminDeleteUserCommand,
    ListUsersInGroupCommand,
    AdminAddUserToGroupCommand,
    AdminResetUserPasswordCommand,
    AdminUserGlobalSignOutCommand,
    AdminRemoveUserFromGroupCommand,
    AdminSetUserMFAPreferenceCommand,
    AdminUpdateUserAttributesCommand } from "@aws-sdk/client-cognito-identity-provider";

const commands = {
    ListUsersCommand,
    ListGroupsCommand,
    AdminGetUserCommand,
    AdminCreateUserCommand,
    AdminDisableUserCommand,
    AdminEnableUserCommand,
    AdminDeleteUserCommand,
    ListUsersInGroupCommand,
    AdminAddUserToGroupCommand,
    AdminResetUserPasswordCommand,
    AdminUserGlobalSignOutCommand,
    AdminRemoveUserFromGroupCommand,
    AdminSetUserMFAPreferenceCommand,
    AdminUpdateUserAttributesCommand
};

class EosAwsCognitoAdmin {

    constructor(identityPoolId, region, userPoolId =  null, token = null, logins = {})
    {
        const cognitoIdentityClient = new CognitoIdentityClient({
          region: region
        });  
        //uses the Auth user IAM profile in the identity pool
        if(logins){
            this.client = new CognitoIdentityProviderClient({
                region: region,
                credentials: fromCognitoIdentityPool({
                    client: cognitoIdentityClient,
                    identityPoolId: identityPoolId,
                    logins: this.createCognitoLoginKey(logins, token, userPoolId, region)
                })
            });
        }
        else //uses the UnAuth user IAM profile in the identity pool
        {
            this.client = new CognitoIdentityProviderClient({
                region: region,
                credentials: fromCognitoIdentityPool({
                    client: cognitoIdentityClient,
                    identityPoolId: identityPoolId                    
                })
            });
        }
            
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // Commands to create, delete, disable, enable users
    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    adminCreateNewUser(
        username, 
        userpoolId = null, 
        UserAttributes = null,
        MessageAction = null, 
        DesiredDeliveryMediums = 'EMAIL',          
        TemporaryPassword = null, 
        ValidationData = null, 
        ForceAliasCreation = null, 
        ClientMetadata = null)
    {
        return this.initAdminCommand('AdminCreateUserCommand', {
            Username:username, 
            UserPoolId:userpoolId,
            UserAttributes: UserAttributes,
            MessageAction: MessageAction,
            DesiredDeliveryMediums: DesiredDeliveryMediums,
            TemporaryPassword: TemporaryPassword,
            ValidationData: ValidationData,
            ForceAliasCreation: ForceAliasCreation,
            ClientMetadata: ClientMetadata
        });
    }

    adminDisableUser(username, userpoolId = null)
    {
        return this.initAdminCommand('AdminDisableUserCommand', {Username:username, UserPoolId:userpoolId});      
    }

    adminEnableUser(username, userpoolId = null)
    {
        return this.initAdminCommand('AdminEnableUserCommand', {Username:username, UserPoolId:userpoolId});
    }

    adminDeleteUser(username, userpoolId = null)
    {
        return this.initAdminCommand('AdminDeleteUserCommand', {Username:username, UserPoolId:userpoolId});
    }

    ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // Commands to enable and disable mfa
    ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    
    adminDisableSmsMfa(username, userpoolId = null)
    {        
        const SMSMfaSettings = {
            Enabled: false,
            PreferredMfa: false
        }
        return this.adminSetUserMFAPreference(username, userpool, SMSMfaSettings);
    }

    adminEnableSmsMfa(username, userpoolId = null)
    {        
        const SMSMfaSettings = {
            Enabled: true,
            PreferredMfa: true
        }
        return this.adminSetUserMFAPreference(username, userpool, SMSMfaSettings);
    }

    adminDisableSoftwareMfa(username, userpoolId = null)
    {        
        const SoftwareTokenMfaSettings = {
            Enabled: false,
            PreferredMfa: false
        }
        return this.adminSetUserMFAPreference(username, userpool, null, SoftwareTokenMfaSettings);
    }

    adminEnableSoftwareMfa(username, userpoolId = null)
    {        
        const SoftwareTokenMfaSettings = {
            Enabled: true,
            PreferredMfa: true
        }
        return this.adminSetUserMFAPreference(username, userpool, null, SoftwareTokenMfaSettings);
    }

    /////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // sign a user out globally
    /////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    adminUserGlobalSignOut(username, userpoolId = null)
    {
        return this.initAdminCommand('AdminUserGlobalSignOutCommand', {Username:username, UserPoolId:userpoolId});
    }

    ///////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // Update a users attributes
    ///////////////////////////////////////////////////////////////////////////////////////////////////////////////

    adminUpdateUserAttributes(username, UserAttributes = [], userpoolId = null, ClientMetadata = null)
    {
        return this.initAdminCommand('AdminUpdateUserAttributesCommand', {
            Username:username, 
            UserPoolId:userpoolId,
            UserAttributes: UserAttributes,
            ClientMetadata: ClientMetadata
        });
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // commands to list users and groups
    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    adminListUsers(userpoolId = null, AttributesToGet = null, Filter = null, Limit = null, PaginationToken = null)
    {
        return this.initAdminCommand('ListUsersCommand', {
            UserPoolId:userpoolId, 
            AttributesToGet: AttributesToGet, 
            Filter: Filter, 
            Limit: Limit, 
            PaginationToken: PaginationToken});
    }

    adminListGroups(userpoolId = null, Limit = null, NextToken = null)
    {
        return this.initAdminCommand('ListGroupsCommand', {
            UserPoolId:userpoolId,             
            Limit: Limit, 
            NextToken: NextToken});
    }

    adminListUsersInGroup(userpoolId = null, GroupName = null, Limit = null, NextToken = null)
    {
        return this.initAdminCommand('ListUsersInGroupCommand', {
            UserPoolId:userpoolId, 
            GroupName: GroupName,            
            Limit: Limit, 
            NextToken: NextToken});
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // commands to manipulate groups
    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    adminAddUserToGroup(username, userpoolId = null, GroupName = null)
    {
        return this.initAdminCommand('AdminAddUserToGroupCommand', {
            UserPoolId:userpoolId, 
            Username: username,
            GroupName: GroupName});
    }

    adminRemoveUserFromGroup(username, userpoolId = null, GroupName = null)
    {
        return this.initAdminCommand('AdminRemoveUserFromGroupCommand', {
            UserPoolId:userpoolId, 
            Username: username,
            GroupName: GroupName});
    }


    ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // Private functions
    ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    
    adminSetUserMFAPreference(username, userpoolId = null, SMSMfaSettings = null, SoftwareTokenMfaSettings = null)
    {
        return this.initAdminCommand('AdminSetUserMFAPreferenceCommand', {
            Username: username, 
            UserPoolId: userpool, 
            SMSMfaSettings: SMSMfaSettings, 
            SoftwareTokenMfaSettings: SoftwareTokenMfaSettings});       
    }
    

    createCognitoLoginKey(logins, token, userPoolId = null, region = null)
    {
        if(token !== null && userPoolId !== null && region !== null)
            logins["cognito-idp."+region+".amazonaws.com/"+userPoolId] = token;
        return logins;
    }

    initAdminCommand(requiredCommand, options)
    {        
        if(!options.UserPoolId)
            return new Promise((resolve, reject) => {
                reject('UserPoolId cannot be null');
            });
        const command = this.createCommandObject(requiredCommand, options);
        return this.client.send(command);
    }

    createCommandObject(command, options)
    {
        return new commands[command](options);
    }
}

export {EosAwsCognitoAdmin};
export default EosAwsCognitoAdmin;