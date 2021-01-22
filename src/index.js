import {AuthenticationDetails, CognitoUserPool, CognitoUser} from 'amazon-cognito-identity-js';

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

    constructor(UserDetails = {})
    {
        this.userDetails = UserDetails;
    }
}

class UserAuthenticationData {
    constructor(Username, password)
    {
        this.authenticationDetails = new AmazonCognitoIdentity.AuthenticationDetails(
            {
                Username: Username,
                Password: password
            }
        );
    }

    getAuthenticationData(){
        return this.authenticationDetails;
    }
}

class UserPool {
    constructor(EosPoolData)
    {
        this.userPool = AmazonCognitoIdentity.CognitoUserPool(EosPoolData.getPoolData());
    }

    getUserPool(){
        return this.userPool;
    }
}

class EosCognitoUser {
    constructor(Username, UserPool)
    {
        this.cognitoUser = new AmazonCognitoIdentity.CognitoUser({
            Username: Username,
            Pool: UserPool
        });
    }

    getCognitoUser(){
        return this.cognitoUser;
    }
}

class EosAwsCognito {

    constructor(EosPoolData)
    {
        this.poolData = EosPoolData.getPoolData();
    }

    login(User)
    {
        const authDetails = new UserAuthenticationData(User.username, User.password);
        const userPool = new UserPool(this.poolData);
        const cognitoUser = new EosCognitoUser(User.username, userPool);
        return new Promise((resolve, reject) => {
            cognitoUser.authenticateUser(authDetails, {
                onSuccess: (result) => {
                    resolve(result);
                },
                onFailure: (err) => {
                    reject(err);
                }
            })
        });
    }

    registerNewUser(User)
    {

    }

    logout(){}


}

export {EosAwsCognito, EosPoolData};
export default {EosAwsCognito, EosPoolData};
