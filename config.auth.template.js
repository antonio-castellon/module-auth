module.exports = {
    url: 'ldap://<address>:389'
    ,DOMAIN:'<domain>'
    ,baseDN: '<baseDN>'
    ,username: '<user-ldap>'
    ,password: '<password>'
    ,NTLM_DEBUG: false /* to activate log mssages from NTLM interface */

    ,CNAME: 'dev.example.com'

    ,passToken: '<passphrase-optional>'  /* if doesn't exists the module generates ones automatically */
    ,EXPIRES: 86400                     /* expires in 24 hours */

    ,MOCKUP_USERS : ['acastellon','rlopez']
    ,MOCKUP_ROLES : ['User','CManager']
    ,ROLES : {
        'User': 'GI RD USER '
        , 'Admin': 'GI RD  ADMINISTRATOR '
        , 'Viewer': 'GI RD  VIEWER '
    }
}