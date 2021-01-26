const enableMfaSettings = {
    PreferredMfa: true,
    Enabled: true,
};

const disableMfaSettings = {
    PreferredMfa: false,
    Enabled: false,
};

const mfaTypes = 
{
    Software: 'SOFTWARE_TOKEN_MFA',
    Sms: 'SMS_MFA'
};

export {enableMfaSettings, disableMfaSettings, mfaTypes};
export default {enableMfaSettings, disableMfaSettings, mfaTypes};