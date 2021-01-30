import {AuthenticationDetails, CognitoUserPool, CognitoUser, CognitoUserAttribute} from 'amazon-cognito-identity-js';

class EosPoolData {

    constructor(UserPoolId, ClientId)
    {
        this.UserPoolId = UserPoolId;
        this.ClientId = ClientId;
    }

    getPoolData()
    {
        return {
            UserPoolId : this.UserPoolId,
            ClientId: this.ClientId
        }
    }
}

class User {

    constructor(username, password, attributeList = [])
    {
        this.username = username;
        this.password = password;
        this.attributeList = [];
        attributeList.forEach(attribute => {
            this.attributeList.push(new CognitoUserAttribute(attribute));
        })
    }
}

class UserAuthenticationData extends AuthenticationDetails {

    constructor(Username, password)
    {
        super({
                Username: Username,
                Password: password
            });
        
    }
}

class UserPool extends CognitoUserPool
{
    constructor(EosPoolData)
    {
        super(EosPoolData.getPoolData());
    }

    
}

class EosCognitoUser extends CognitoUser {
    constructor(Username, UserPool)
    {
        super({
            Username: Username,
            Pool: UserPool
        });
    }
}

export {EosCognitoUser, UserPool, UserAuthenticationData, User, EosPoolData};
export default {EosCognitoUser, UserPool, UserAuthenticationData, User, EosPoolData};