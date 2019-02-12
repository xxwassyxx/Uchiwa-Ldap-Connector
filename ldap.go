package ldap

import (
  "gopkg.in/ldap.v3"
  "crypto/tls"
  "fmt"
  "github.com/sensu/uchiwa/uchiwa/authentication"
  "github.com/sensu/uchiwa/uchiwa/config"
)

var ls config.Ldap

func LoadConfig(c config.Ldap){
  ls = c
}

func LdapAuth(u, p string) (*authentication.User, error) {
  
  var (
    fn    string = ""
    email string = ""
    role authentication.Role
  )


  tlsConfig := &tls.Config{InsecureSkipVerify: ls.Insecure}
  l, err := ldap.DialTLS("tcp", fmt.Sprintf("%s:%d", ls.Server, ls.Port), tlsConfig)
  if err != nil {
    return &authentication.User{}, fmt.Errorf("unable to connect to AD server")
  }
  defer l.Close()

  err = l.Bind(ls.BindUser, ls.BindPass)
  if err != nil {
    return &authentication.User{}, fmt.Errorf("unable to Auth with AD server")
  }
  // Search for the given username
  userSearchRequest := ldap.NewSearchRequest(
    ls.BaseDN,
    ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
    fmt.Sprintf("(%s=%s)", ls.UserAttribute, u),
    []string{"dn", "mail", "cn", "ou"},
    nil,
  )

  sr, err := l.Search(userSearchRequest)
  if err != nil {
    return &authentication.User{}, fmt.Errorf("unable to lookup user '%s' in ad", u)
  }

  if len(sr.Entries) < 1 {
    return &authentication.User{}, fmt.Errorf("unable to find user '%s' in ad", u)
  }

  userdn := sr.Entries[0].DN
  for i := range sr.Entries {
    for _, value := range sr.Entries[i].Attributes {
      switch {
        case value.Name == "cn":
        fn = value.Values[0]
        case value.Name == "mail":
        email = value.Values[0]
      }
    }
  }

  // Bind as the user to verify their password
  err = l.Bind(userdn, p)
  if err != nil {
    return &authentication.User{}, fmt.Errorf("invalid user '%s' or invalid password", u)
  }

  // Rebind as the read only user for any further queries
  err = l.Bind(ls.BindUser, ls.BindPass)
  if err != nil {
    return &authentication.User{}, fmt.Errorf("invalid user '%s' or invalid password", u)
  }

  // Search groups for the user
  for _, i := range ls.Roles {
    for _, group := range i.Members {
      groupSearchRequest := ldap.NewSearchRequest(
        ls.BaseDN,
        ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
        fmt.Sprintf("(&(objectClass=user)(%s=%s)(memberof=%s))", ls.UserAttribute, u, group),
        []string{},
        nil,
      )
      gr, err := l.Search(groupSearchRequest)
      if err != nil {
        return &authentication.User{}, fmt.Errorf("unable to find user '%s' in defined groups in ad", u)
      }
      if len(gr.Entries) < 1 { break }
      role.Readonly = i.Readonly
      role.Name = i.Name
      role.Datacenters = i.Datacenters
    }
  }
  fmt.Println("Successfully authenticated user", u)
  return &authentication.User{ID: 0, Username: u, FullName: fn, Email: email, Role: authentication.Role{Name: role.Name,  Readonly: role.Readonly, Datacenters: role.Datacenters}}, nil
}