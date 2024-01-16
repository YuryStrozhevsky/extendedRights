# Basic information
The project is about getting information for all [**Extended Rights**](https://learn.microsoft.com/en-us/windows/win32/adschema/extended-rights) and [**Property Sets**](https://learn.microsoft.com/en-us/windows/win32/adschema/property-sets). It is very hard to find all necessary information from official Microsoft documents, but apparently all the information exists in every Windows Domain. In this project I would like to give an example of how information about **Extender Rigths** could be retrived via pure Windows LDAP functions. Also it is built using Visual Studio 2022 and the code requires C++ 23 language standard.

# Search algorithm
1. There are "namespace contexts" under "RootDSE". In this search we would need "Schema" and "Configuration" namespaces;
2. Firstly we need to gather all attributes from "Schema" namespace (LDAP filter "schemaIdGuid=*"). We are interested in following attributes:
	* _ldapDisplayName_ (for short name of the attribute);
	* _adminDescription_ (for long description of the attribute);
	* _attributeSecurityGUID_. If this value exists in schema attribute then the attribute included in any _extended rights property set_. The value in _attributeSecurityGUID_ would be equal with _rightsGuid_ from _extended right_ attribute;
	* _schemaIdGuid_ (major GUID for the attrubute);
3. The _attributeSecurityGUID_ and _schemaIdGuid_ are both pure binary attributes (GUIDs in these attributes stored in binary form, not as a string). For the sake of our next steps we converting them to string represenation of GUIDs;
4. Then we store all inside two maps. First map is for major information about each attribute with key=_schemaIdGuid_. Second map is a multimap, storing information about _extended rights property set_;
5. Then we gather all _extender rights_ from "Configuration" namespace. Simpliest LDAP filter for this would be "rightsGuid=*". Necessary attributes are:
	* _name_ (for short name of _extended right_);
	* _displayName_ (for full description of _extended right_);
	* _appliesTo_ (this has multiple values pointed to object classes to which the _extended right_ applies);
	* _rightsGuid_ (main GUID of the _extended right_);
6. The all that we need is to find all attributes in _appliesTo_ and also find all values from multimap where key equal to _rightsGuid_ (this would be displayed under "Consists Of");

# Code optimizations
It is possible to optimize the code by gathering all _extended rigths_ first and then create a LDAP filter with only necessary GUIDs for schema attributes. But I have not done this just becase in the present state my code is easier to understand, IMHO.

# Example output
<details>
<summary>Output from Windows Server 2019</summary>

```console
=================================
GUID: ab721a52-1e2f-11d0-9819-00aa0040529b
Name: Domain-Administer-Server
Display Name: Domain Administer Server
Applies To:
	bf967aad-0de6-11d0-a285-00aa003049e2 (samServer, Sam-Server)
=================================
GUID: ab721a53-1e2f-11d0-9819-00aa0040529b
Name: User-Change-Password
Display Name: Change Password
Applies To:
	4828cc14-1437-45bc-9b07-ad6f015e5f28 (inetOrgPerson, Represents people who are associated with an organization in some way.)
	ce206244-5827-4a86-ba1c-1c0c386c1b64 (msDS-ManagedServiceAccount, Service account class is used to create accounts that are used for running Windows services.)
	bf967a86-0de6-11d0-a285-00aa003049e2 (computer, Computer)
	bf967aba-0de6-11d0-a285-00aa003049e2 (user, User)
=================================
GUID: 00299570-246d-11d0-a768-00aa006e0529
Name: User-Force-Change-Password
Display Name: Reset Password
Applies To:
	4828cc14-1437-45bc-9b07-ad6f015e5f28 (inetOrgPerson, Represents people who are associated with an organization in some way.)
	ce206244-5827-4a86-ba1c-1c0c386c1b64 (msDS-ManagedServiceAccount, Service account class is used to create accounts that are used for running Windows services.)
	bf967a86-0de6-11d0-a285-00aa003049e2 (computer, Computer)
	bf967aba-0de6-11d0-a285-00aa003049e2 (user, User)
=================================
GUID: ab721a54-1e2f-11d0-9819-00aa0040529b
Name: Send-As
Display Name: Send As
Applies To:
	7b8b558a-93a5-4af7-adca-c017e67f1057 (msDS-GroupManagedServiceAccount, The group managed service account class is used to create an account which can be shared by different computers to run Windows services.)
	4828cc14-1437-45bc-9b07-ad6f015e5f28 (inetOrgPerson, Represents people who are associated with an organization in some way.)
	ce206244-5827-4a86-ba1c-1c0c386c1b64 (msDS-ManagedServiceAccount, Service account class is used to create accounts that are used for running Windows services.)
	bf967a86-0de6-11d0-a285-00aa003049e2 (computer, Computer)
	bf967aba-0de6-11d0-a285-00aa003049e2 (user, User)
=================================
GUID: ab721a56-1e2f-11d0-9819-00aa0040529b
Name: Receive-As
Display Name: Receive As
Applies To:
	7b8b558a-93a5-4af7-adca-c017e67f1057 (msDS-GroupManagedServiceAccount, The group managed service account class is used to create an account which can be shared by different computers to run Windows services.)
	4828cc14-1437-45bc-9b07-ad6f015e5f28 (inetOrgPerson, Represents people who are associated with an organization in some way.)
	ce206244-5827-4a86-ba1c-1c0c386c1b64 (msDS-ManagedServiceAccount, Service account class is used to create accounts that are used for running Windows services.)
	bf967a86-0de6-11d0-a285-00aa003049e2 (computer, Computer)
	bf967aba-0de6-11d0-a285-00aa003049e2 (user, User)
=================================
GUID: ab721a55-1e2f-11d0-9819-00aa0040529b
Name: Send-To
Display Name: Send To
Applies To:
	bf967a9c-0de6-11d0-a285-00aa003049e2 (group, Group)
=================================
GUID: c7407360-20bf-11d0-a768-00aa006e0529
Name: Domain-Password
Display Name: Domain Password & Lockout Policies
Applies To:
	19195a5b-6da0-11d0-afd3-00c04fd930c9 (domainDNS, Domain-DNS)
	19195a5a-6da0-11d0-afd3-00c04fd930c9 (domain, Domain)
Consists Of:
	bf9679a4-0de6-11d0-a285-00aa003049e2 (lockOutObservationWindow, Lock-Out-Observation-Window)
	bf9679a5-0de6-11d0-a285-00aa003049e2 (lockoutDuration, Lockout-Duration)
	bf9679a6-0de6-11d0-a285-00aa003049e2 (lockoutThreshold, Lockout-Threshold)
	bf9679bb-0de6-11d0-a285-00aa003049e2 (maxPwdAge, Max-Pwd-Age)
	bf9679c2-0de6-11d0-a285-00aa003049e2 (minPwdAge, Min-Pwd-Age)
	bf9679c3-0de6-11d0-a285-00aa003049e2 (minPwdLength, Min-Pwd-Length)
	bf967a09-0de6-11d0-a285-00aa003049e2 (pwdHistoryLength, Pwd-History-Length)
	bf967a0b-0de6-11d0-a285-00aa003049e2 (pwdProperties, Pwd-Properties)
=================================
GUID: 59ba2f42-79a2-11d0-9020-00c04fc2d3cf
Name: General-Information
Display Name: General Information
Applies To:
	4828cc14-1437-45bc-9b07-ad6f015e5f28 (inetOrgPerson, Represents people who are associated with an organization in some way.)
	bf967aba-0de6-11d0-a285-00aa003049e2 (user, User)
Consists Of:
	bf967919-0de6-11d0-a285-00aa003049e2 (adminDescription, Admin-Description)
	bf967938-0de6-11d0-a285-00aa003049e2 (codePage, Code-Page)
	5fd42471-1262-11d0-a060-00aa006c33ed (countryCode, Country-Code)
	bf967953-0de6-11d0-a285-00aa003049e2 (displayName, Display-Name)
	bf9679e8-0de6-11d0-a285-00aa003049e2 (objectSid, Object-Sid)
	bf967a00-0de6-11d0-a285-00aa003049e2 (primaryGroupID, Primary-Group-ID)
	3e0abfd0-126a-11d0-a060-00aa006c33ed (sAMAccountName, SAM-Account-Name)
	6e7b626c-64f2-11d0-afd2-00c04fd930c9 (sAMAccountType, SAM-Account-Type)
	c3dbafa6-33df-11d2-98b2-0000f87a57d4 (sDRightsEffective, SD-Rights-Effective)
	bf967984-0de6-11d0-a285-00aa003049e2 (showInAdvancedViewOnly, Show-In-Advanced-View-Only)
	17eb4278-d167-11d0-b002-0000f80367c1 (sIDHistory, SID-History)
	0bb0fca0-1e89-429f-901a-1413894d9f59 (uid, A user ID.)
	bf967a6a-0de6-11d0-a285-00aa003049e2 (comment, User-Comment)
=================================
GUID: 4c164200-20c0-11d0-a768-00aa006e0529
Name: User-Account-Restrictions
Display Name: Account Restrictions
Applies To:
	7b8b558a-93a5-4af7-adca-c017e67f1057 (msDS-GroupManagedServiceAccount, The group managed service account class is used to create an account which can be shared by different computers to run Windows services.)
	4828cc14-1437-45bc-9b07-ad6f015e5f28 (inetOrgPerson, Represents people who are associated with an organization in some way.)
	ce206244-5827-4a86-ba1c-1c0c386c1b64 (msDS-ManagedServiceAccount, Service account class is used to create accounts that are used for running Windows services.)
	bf967a86-0de6-11d0-a285-00aa003049e2 (computer, Computer)
	bf967aba-0de6-11d0-a285-00aa003049e2 (user, User)
Consists Of:
	bf967915-0de6-11d0-a285-00aa003049e2 (accountExpires, Account-Expires)
	2cc4b836-b63f-4940-8d23-ea7acf06af56 (msDS-User-Account-Control-Computed, ms-DS-User-Account-Control-Computed)
	add5cf10-7b09-4449-9ae6-2534148f8a72 (msDS-UserPasswordExpiryTimeComputed, Contains the expiry time for the user's current password)
	bf967a0a-0de6-11d0-a285-00aa003049e2 (pwdLastSet, Pwd-Last-Set)
	bf967a68-0de6-11d0-a285-00aa003049e2 (userAccountControl, User-Account-Control)
	bf967a6d-0de6-11d0-a285-00aa003049e2 (userParameters, User-Parameters)
	3f78c3e5-f79a-46bd-a0b8-9d18116ddc79 (msDS-AllowedToActOnBehalfOfOtherIdentity, This attribute is used for access checks to determine if a requestor has permission to act on the behalf of other identities to services running as this account.)
=================================
GUID: 5f202010-79a5-11d0-9020-00c04fc2d4cf
Name: User-Logon
Display Name: Logon Information
Applies To:
	4828cc14-1437-45bc-9b07-ad6f015e5f28 (inetOrgPerson, Represents people who are associated with an organization in some way.)
	bf967aba-0de6-11d0-a285-00aa003049e2 (user, User)
Consists Of:
	bf96792e-0de6-11d0-a285-00aa003049e2 (badPwdCount, Bad-Pwd-Count)
	bf967985-0de6-11d0-a285-00aa003049e2 (homeDirectory, Home-Directory)
	bf967986-0de6-11d0-a285-00aa003049e2 (homeDrive, Home-Drive)
	bf967996-0de6-11d0-a285-00aa003049e2 (lastLogoff, Last-Logoff)
	bf967997-0de6-11d0-a285-00aa003049e2 (lastLogon, Last-Logon)
	c0e20a04-0e5a-4ff3-9482-5efeaecd7060 (lastLogonTimestamp, Last-Logon-Timestamp)
	bf9679aa-0de6-11d0-a285-00aa003049e2 (logonCount, Logon-Count)
	bf9679ab-0de6-11d0-a285-00aa003049e2 (logonHours, Logon-Hours)
	bf9679ac-0de6-11d0-a285-00aa003049e2 (logonWorkstation, Logon-Workstation)
	bf967a05-0de6-11d0-a285-00aa003049e2 (profilePath, Profile-Path)
	bf9679a8-0de6-11d0-a285-00aa003049e2 (scriptPath, Script-Path)
	bf9679d7-0de6-11d0-a285-00aa003049e2 (userWorkstations, User-Workstations)
=================================
GUID: bc0ac240-79a9-11d0-9020-00c04fc2d4cf
Name: Membership
Display Name: Group Membership
Applies To:
	4828cc14-1437-45bc-9b07-ad6f015e5f28 (inetOrgPerson, Represents people who are associated with an organization in some way.)
	bf967aba-0de6-11d0-a285-00aa003049e2 (user, User)
Consists Of:
	bf967991-0de6-11d0-a285-00aa003049e2 (memberOf, Is-Member-Of-DL)
	bf9679c0-0de6-11d0-a285-00aa003049e2 (member, Member)
=================================
GUID: a1990816-4298-11d1-ade2-00c04fd8d5cd
Name: Open-Address-Book
Display Name: Open Address List
Applies To:
	3e74f60f-3e73-11d1-a9c0-0000f80367c1 (addressBookContainer, Address-Book-Container)
=================================
GUID: 77b5b886-944a-11d1-aebd-0000f80367c1
Name: Personal-Information
Display Name: Personal Information
Applies To:
	7b8b558a-93a5-4af7-adca-c017e67f1057 (msDS-GroupManagedServiceAccount, The group managed service account class is used to create an account which can be shared by different computers to run Windows services.)
	641e87a4-8326-4771-ba2d-c706df35e35a (msDS-CloudExtensions, A collection of attributes used to house arbitrary cloud-relevant strings.)
	4828cc14-1437-45bc-9b07-ad6f015e5f28 (inetOrgPerson, Represents people who are associated with an organization in some way.)
	ce206244-5827-4a86-ba1c-1c0c386c1b64 (msDS-ManagedServiceAccount, Service account class is used to create accounts that are used for running Windows services.)
	bf967a86-0de6-11d0-a285-00aa003049e2 (computer, Computer)
	5cb41ed0-0e4c-11d0-a286-00aa003049e2 (contact, Contact)
	bf967aba-0de6-11d0-a285-00aa003049e2 (user, User)
Consists Of:
	f0f8ff84-1191-11d0-a060-00aa006c33ed (streetAddress, Address)
	16775781-47f3-11d1-a9c3-0000f80367c1 (homePostalAddress, Address-Home)
	0296c11c-40da-11d1-a9c0-0000f80367c1 (assistant, Assistant)
	bf96793e-0de6-11d0-a285-00aa003049e2 (info, Comment)
	bf967945-0de6-11d0-a285-00aa003049e2 (c, Country-Name)
	bf967974-0de6-11d0-a285-00aa003049e2 (facsimileTelephoneNumber, Facsimile-Telephone-Number)
	bf96798d-0de6-11d0-a285-00aa003049e2 (internationalISDNNumber, International-ISDN-Number)
	bf9679a2-0de6-11d0-a285-00aa003049e2 (l, Locality-Name)
	80641043-15a2-40e1-92a2-8ca866f70776 (msDS-HostServiceAccount, Service Accounts configured to run on this computer.)
	20119867-1d04-4ab7-9371-cfc3d5df0afd (msDS-SupportedEncryptionTypes, The encryption algorithms supported by user, computer or trust accounts. The KDC uses this information while generating a service ticket for this account. Services/Computers may automatically update this attribute on their respective accounts in Active Directory, and therefore need write access to this attribute.)
	011929e6-8b5d-4258-b64a-00b0b4949747 (msDS-LastSuccessfulInteractiveLogonTime, The time that the correct password was presented during a C-A-D logon.)
	c7e7dafa-10c3-4b8b-9acd-54f11063742e (msDS-LastFailedInteractiveLogonTime, The time that an incorrect password was presented during a C-A-D logon.)
	dc3ca86f-70ad-4960-8425-a4d6313d93dd (msDS-FailedInteractiveLogonCount, The total number of failed interactive logons since this feature was turned on.)
	c5d234e5-644a-4403-a665-e26e0aef5e98 (msDS-FailedInteractiveLogonCountAtLastSuccessfulLogon, The total number of failed interactive logons up until the last successful C-A-D logon.)
	9a0dc33c-c100-11d1-bbc5-0080c76670c0 (mSMQDigests, MSMQ-Digests)
	9a0dc33b-c100-11d1-bbc5-0080c76670c0 (mSMQSignCertificates, MSMQ-Sign-Certificates)
	16775858-47f3-11d1-a9c3-0000f80367c1 (personalTitle, Personal-Title)
	0296c11d-40da-11d1-a9c0-0000f80367c1 (otherFacsimileTelephoneNumber, Phone-Fax-Other)
	f0f8ffa2-1191-11d0-a060-00aa006c33ed (otherHomePhone, Phone-Home-Other)
	f0f8ffa1-1191-11d0-a060-00aa006c33ed (homePhone, Phone-Home-Primary)
	4d146e4b-48d4-11d1-a9c3-0000f80367c1 (otherIpPhone, Phone-Ip-Other)
	4d146e4a-48d4-11d1-a9c3-0000f80367c1 (ipPhone, Phone-Ip-Primary)
	0296c11f-40da-11d1-a9c0-0000f80367c1 (primaryInternationalISDNNumber, Phone-ISDN-Primary)
	0296c11e-40da-11d1-a9c0-0000f80367c1 (otherMobile, Phone-Mobile-Other)
	f0f8ffa3-1191-11d0-a060-00aa006c33ed (mobile, Phone-Mobile-Primary)
	f0f8ffa5-1191-11d0-a060-00aa006c33ed (otherTelephone, Phone-Office-Other)
	f0f8ffa4-1191-11d0-a060-00aa006c33ed (otherPager, Phone-Pager-Other)
	f0f8ffa6-1191-11d0-a060-00aa006c33ed (pager, Phone-Pager-Primary)
	bf9679f7-0de6-11d0-a285-00aa003049e2 (physicalDeliveryOfficeName, Physical-Delivery-Office-Name)
	8d3bca50-1d7e-11d0-a081-00aa006c33ed (thumbnailPhoto, Picture)
	bf9679fb-0de6-11d0-a285-00aa003049e2 (postOfficeBox, Post-Office-Box)
	bf9679fc-0de6-11d0-a285-00aa003049e2 (postalAddress, Postal-Address)
	bf9679fd-0de6-11d0-a285-00aa003049e2 (postalCode, Postal-Code)
	bf9679fe-0de6-11d0-a285-00aa003049e2 (preferredDeliveryMethod, Preferred-Delivery-Method)
	bf967a10-0de6-11d0-a285-00aa003049e2 (registeredAddress, Registered-Address)
	bf967a39-0de6-11d0-a285-00aa003049e2 (st, State-Or-Province-Name)
	bf967a3a-0de6-11d0-a285-00aa003049e2 (street, Street-Address)
	bf967a49-0de6-11d0-a285-00aa003049e2 (telephoneNumber, Telephone-Number)
	bf967a4a-0de6-11d0-a285-00aa003049e2 (teletexTerminalIdentifier, Teletex-Terminal-Identifier)
	bf967a4b-0de6-11d0-a285-00aa003049e2 (telexNumber, Telex-Number)
	0296c121-40da-11d1-a9c0-0000f80367c1 (primaryTelexNumber, Telex-Primary)
	bf967a69-0de6-11d0-a285-00aa003049e2 (userCert, User-Cert)
	9a9a021f-4a5b-11d1-a9c3-0000f80367c1 (userSharedFolder, User-Shared-Folder)
	9a9a0220-4a5b-11d1-a9c3-0000f80367c1 (userSharedFolderOther, User-Shared-Folder-Other)
	e16a9db2-403c-11d1-a9c0-0000f80367c1 (userSMIMECertificate, User-SMIME-Certificate)
	bf967a7b-0de6-11d0-a285-00aa003049e2 (x121Address, X121-Address)
	bf967a7f-0de6-11d0-a285-00aa003049e2 (userCertificate, X509-Cert)
	a11703b7-5641-4d9c-863e-5fb3325e74e0 (msDS-GeoCoordinatesAltitude, ms-DS-GeoCoordinates-Altitude)
	dc66d44e-3d43-40f5-85c5-3c12e169927e (msDS-GeoCoordinatesLatitude, ms-DS-GeoCoordinates-Latitude)
	94c42110-bae4-4cea-8577-af813af5da25 (msDS-GeoCoordinatesLongitude, ms-DS-GeoCoordinates-Longitude)
	9709eaaf-49da-4db2-908a-0446e5eab844 (msDS-cloudExtensionAttribute1, An attribute used to house an arbitrary cloud-relevant string)
	f34ee0ac-c0c1-4ba9-82c9-1a90752f16a5 (msDS-cloudExtensionAttribute2, An attribute used to house an arbitrary cloud-relevant string)
	82f6c81a-fada-4a0d-b0f7-706d46838eb5 (msDS-cloudExtensionAttribute3, An attribute used to house an arbitrary cloud-relevant string)
	9cbf3437-4e6e-485b-b291-22b02554273f (msDS-cloudExtensionAttribute4, An attribute used to house an arbitrary cloud-relevant string)
	2915e85b-e347-4852-aabb-22e5a651c864 (msDS-cloudExtensionAttribute5, An attribute used to house an arbitrary cloud-relevant string)
	60452679-28e1-4bec-ace3-712833361456 (msDS-cloudExtensionAttribute6, An attribute used to house an arbitrary cloud-relevant string)
	4a7c1319-e34e-40c2-9d00-60ff7890f207 (msDS-cloudExtensionAttribute7, An attribute used to house an arbitrary cloud-relevant string)
	3cd1c514-8449-44ca-81c0-021781800d2a (msDS-cloudExtensionAttribute8, An attribute used to house an arbitrary cloud-relevant string)
	0a63e12c-3040-4441-ae26-cd95af0d247e (msDS-cloudExtensionAttribute9, An attribute used to house an arbitrary cloud-relevant string)
	670afcb3-13bd-47fc-90b3-0a527ed81ab7 (msDS-cloudExtensionAttribute10, An attribute used to house an arbitrary cloud-relevant string)
	9e9ebbc8-7da5-42a6-8925-244e12a56e24 (msDS-cloudExtensionAttribute11, An attribute used to house an arbitrary cloud-relevant string)
	3c01c43d-e10b-4fca-92b2-4cf615d5b09a (msDS-cloudExtensionAttribute12, An attribute used to house an arbitrary cloud-relevant string)
	28be464b-ab90-4b79-a6b0-df437431d036 (msDS-cloudExtensionAttribute13, An attribute used to house an arbitrary cloud-relevant string)
	cebcb6ba-6e80-4927-8560-98feca086a9f (msDS-cloudExtensionAttribute14, An attribute used to house an arbitrary cloud-relevant string)
	aae4d537-8af0-4daa-9cc6-62eadb84ff03 (msDS-cloudExtensionAttribute15, An attribute used to house an arbitrary cloud-relevant string)
	9581215b-5196-4053-a11e-6ffcafc62c4d (msDS-cloudExtensionAttribute16, An attribute used to house an arbitrary cloud-relevant string)
	3d3c6dda-6be8-4229-967e-2ff5bb93b4ce (msDS-cloudExtensionAttribute17, An attribute used to house an arbitrary cloud-relevant string)
	88e73b34-0aa6-4469-9842-6eb01b32a5b5 (msDS-cloudExtensionAttribute18, An attribute used to house an arbitrary cloud-relevant string)
	0975fe99-9607-468a-8e18-c800d3387395 (msDS-cloudExtensionAttribute19, An attribute used to house an arbitrary cloud-relevant string)
	f5446328-8b6e-498d-95a8-211748d5acdc (msDS-cloudExtensionAttribute20, An attribute used to house an arbitrary cloud-relevant string)
	bd29bf90-66ad-40e1-887b-10df070419a6 (msDS-ExternalDirectoryObjectId, ms-DS-External-Directory-Object-Id)
=================================
GUID: e45795b2-9455-11d1-aebd-0000f80367c1
Name: Email-Information
Display Name: Phone and Mail Options
Applies To:
	4828cc14-1437-45bc-9b07-ad6f015e5f28 (inetOrgPerson, Represents people who are associated with an organization in some way.)
	bf967a9c-0de6-11d0-a285-00aa003049e2 (group, Group)
	bf967aba-0de6-11d0-a285-00aa003049e2 (user, User)
=================================
GUID: e45795b3-9455-11d1-aebd-0000f80367c1
Name: Web-Information
Display Name: Web Information
Applies To:
	4828cc14-1437-45bc-9b07-ad6f015e5f28 (inetOrgPerson, Represents people who are associated with an organization in some way.)
	5cb41ed0-0e4c-11d0-a286-00aa003049e2 (contact, Contact)
	bf967aba-0de6-11d0-a285-00aa003049e2 (user, User)
Consists Of:
	bf967a7a-0de6-11d0-a285-00aa003049e2 (wWWHomePage, WWW-Home-Page)
	9a9a0221-4a5b-11d1-a9c3-0000f80367c1 (url, WWW-Page-Other)
=================================
GUID: 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2
Name: DS-Replication-Get-Changes
Display Name: Replicating Directory Changes
Applies To:
	bf967a8f-0de6-11d0-a285-00aa003049e2 (dMD, DMD)
	bf967a87-0de6-11d0-a285-00aa003049e2 (configuration, Configuration)
	19195a5b-6da0-11d0-afd3-00c04fd930c9 (domainDNS, Domain-DNS)
=================================
GUID: 1131f6ab-9c07-11d1-f79f-00c04fc2dcd2
Name: DS-Replication-Synchronize
Display Name: Replication Synchronization
Applies To:
	bf967a8f-0de6-11d0-a285-00aa003049e2 (dMD, DMD)
	bf967a87-0de6-11d0-a285-00aa003049e2 (configuration, Configuration)
	19195a5b-6da0-11d0-afd3-00c04fd930c9 (domainDNS, Domain-DNS)
=================================
GUID: 1131f6ac-9c07-11d1-f79f-00c04fc2dcd2
Name: DS-Replication-Manage-Topology
Display Name: Manage Replication Topology
Applies To:
	bf967a8f-0de6-11d0-a285-00aa003049e2 (dMD, DMD)
	bf967a87-0de6-11d0-a285-00aa003049e2 (configuration, Configuration)
	19195a5b-6da0-11d0-afd3-00c04fd930c9 (domainDNS, Domain-DNS)
=================================
GUID: e12b56b6-0a95-11d1-adbb-00c04fd8d5cd
Name: Change-Schema-Master
Display Name: Change Schema Master
Applies To:
	bf967a8f-0de6-11d0-a285-00aa003049e2 (dMD, DMD)
=================================
GUID: d58d5f36-0a98-11d1-adbb-00c04fd8d5cd
Name: Change-Rid-Master
Display Name: Change Rid Master
Applies To:
	6617188d-8f3c-11d0-afda-00c04fd930c9 (rIDManager, RID-Manager)
=================================
GUID: fec364e0-0a98-11d1-adbb-00c04fd8d5cd
Name: Do-Garbage-Collection
Display Name: Do Garbage Collection
Applies To:
	f0f8ffab-1191-11d0-a060-00aa006c33ed (nTDSDSA, NTDS-DSA)
=================================
GUID: 0bc1554e-0a99-11d1-adbb-00c04fd8d5cd
Name: Recalculate-Hierarchy
Display Name: Recalculate Hierarchy
Applies To:
	f0f8ffab-1191-11d0-a060-00aa006c33ed (nTDSDSA, NTDS-DSA)
=================================
GUID: 1abd7cf8-0a99-11d1-adbb-00c04fd8d5cd
Name: Allocate-Rids
Display Name: Allocate Rids
Applies To:
	f0f8ffab-1191-11d0-a060-00aa006c33ed (nTDSDSA, NTDS-DSA)
=================================
GUID: bae50096-4752-11d1-9052-00c04fc2d4cf
Name: Change-PDC
Display Name: Change PDC
Applies To:
	19195a5b-6da0-11d0-afd3-00c04fd930c9 (domainDNS, Domain-DNS)
=================================
GUID: 440820ad-65b4-11d1-a3da-0000f875ae0d
Name: Add-GUID
Display Name: Add GUID
Applies To:
	19195a5b-6da0-11d0-afd3-00c04fd930c9 (domainDNS, Domain-DNS)
=================================
GUID: 014bf69c-7b3b-11d1-85f6-08002be74fab
Name: Change-Domain-Master
Display Name: Change Domain Master
Applies To:
	ef9e60e0-56f7-11d1-a9c6-0000f80367c1 (crossRefContainer, Cross-Ref-Container)
=================================
GUID: e48d0154-bcf8-11d1-8702-00c04fb96050
Name: Public-Information
Display Name: Public Information
Applies To:
	7b8b558a-93a5-4af7-adca-c017e67f1057 (msDS-GroupManagedServiceAccount, The group managed service account class is used to create an account which can be shared by different computers to run Windows services.)
	4828cc14-1437-45bc-9b07-ad6f015e5f28 (inetOrgPerson, Represents people who are associated with an organization in some way.)
	ce206244-5827-4a86-ba1c-1c0c386c1b64 (msDS-ManagedServiceAccount, Service account class is used to create accounts that are used for running Windows services.)
	bf967a86-0de6-11d0-a285-00aa003049e2 (computer, Computer)
	bf967aba-0de6-11d0-a285-00aa003049e2 (user, User)
Consists Of:
	6d05fb41-246b-11d0-a9c8-00aa006c33ed (notes, Additional-Information)
	9a7ad940-ca53-11d1-bbd0-0080c76670c0 (allowedAttributes, Allowed-Attributes)
	9a7ad941-ca53-11d1-bbd0-0080c76670c0 (allowedAttributesEffective, Allowed-Attributes-Effective)
	9a7ad942-ca53-11d1-bbd0-0080c76670c0 (allowedChildClasses, Allowed-Child-Classes)
	9a7ad943-ca53-11d1-bbd0-0080c76670c0 (allowedChildClassesEffective, Allowed-Child-Classes-Effective)
	00fbf30c-91fe-11d1-aebc-0000f80367c1 (altSecurityIdentities, Alt-Security-Identities)
	bf96793f-0de6-11d0-a285-00aa003049e2 (cn, Common-Name)
	f0f8ff88-1191-11d0-a060-00aa006c33ed (company, Company)
	bf96794f-0de6-11d0-a285-00aa003049e2 (department, Department)
	bf967950-0de6-11d0-a285-00aa003049e2 (description, Description)
	bf967954-0de6-11d0-a285-00aa003049e2 (displayNamePrintable, Display-Name-Printable)
	fe6136a0-2073-11d0-a9c2-00aa006c33ed (division, Division)
	bf967961-0de6-11d0-a285-00aa003049e2 (mail, E-mail-Addresses)
	f0f8ff8e-1191-11d0-a060-00aa006c33ed (givenName, Given-Name)
	f0f8ff90-1191-11d0-a060-00aa006c33ed (initials, Initials)
	28630ebc-41d5-11d1-a9c1-0000f80367c1 (legacyExchangeDN, Legacy-Exchange-DN)
	bf9679b5-0de6-11d0-a285-00aa003049e2 (manager, Manager)
	800d94d7-b7a1-42a1-b14d-7cae1423d07f (msDS-AllowedToDelegateTo, Allowed-To-Delegate-To contains a list of SPNs that are used for Constrained Delegation)
	c4af1073-ee50-4be0-b8c0-89a41fe99abe (msDS-Auxiliary-Classes, ms-DS-Auxiliary-Classes)
	e185d243-f6ce-4adb-b496-b0c005d7823c (msDS-Approx-Immed-Subordinates, ms-DS-Approx-Immed-Subordinates)
	4b1cba4e-302f-4134-ac7c-f01f6c797843 (msDS-PhoneticFirstName, Contains the phonetic given name or first name of the person.)
	f217e4ec-0836-4b90-88af-2f5d4bbda2bc (msDS-PhoneticLastName, Contains the phonetic last name of the person.)
	6cd53daf-003e-49e7-a702-6fa896e7a6ef (msDS-PhoneticDepartment, Contains the phonetic department name where the person works.)
	5bd5208d-e5f4-46ae-a514-543bc9c47659 (msDS-PhoneticCompanyName, Contains the phonetic company name where the person works.)
	e21a94e4-2d66-4ce5-b30d-0ef87a776ff0 (msDS-PhoneticDisplayName, The phonetic display name of an object.  In the absence of a phonetic display name the existing display name is used.)
	def449f1-fd3b-4045-98cf-d9658da788b5 (msDS-HABSeniorityIndex, Contains the seniority index as applied by the organization where the person works.)
	773e93af-d3b4-48d4-b3f9-06457602d3d0 (msDS-SourceObjectDN, The string representation of the DN of the object in another forest that corresponds to this object.)
	bf9679e4-0de6-11d0-a285-00aa003049e2 (distinguishedName, Obj-Dist-Name)
	26d97369-6070-11d1-a9c6-0000f80367c1 (objectCategory, Object-Category)
	bf9679e5-0de6-11d0-a285-00aa003049e2 (objectClass, Object-Class)
	bf9679e7-0de6-11d0-a285-00aa003049e2 (objectGUID, Object-Guid)
	bf9679ef-0de6-11d0-a285-00aa003049e2 (o, Organization-Name)
	bf9679f0-0de6-11d0-a285-00aa003049e2 (ou, Organizational-Unit-Name)
	0296c123-40da-11d1-a9c0-0000f80367c1 (otherMailbox, Other-Mailbox)
	bf967a06-0de6-11d0-a285-00aa003049e2 (proxyAddresses, Proxy-Addresses)
	bf967a0e-0de6-11d0-a285-00aa003049e2 (name, RDN)
	bf967a1c-0de6-11d0-a285-00aa003049e2 (directReports, Reports)
	f3a64788-5306-11d1-a9c5-0000f80367c1 (servicePrincipalName, Service-Principal-Name)
	3e74f60e-3e73-11d1-a9c0-0000f80367c1 (showInAddressBook, Show-In-Address-Book)
	bf967a41-0de6-11d0-a285-00aa003049e2 (sn, Surname)
	e0fa1e62-9b45-11d0-afdd-00c04fd930c9 (systemFlags, System-Flags)
	f0f8ffa7-1191-11d0-a060-00aa006c33ed (co, Text-Country)
	bf967a55-0de6-11d0-a285-00aa003049e2 (title, Title)
	28630ebb-41d5-11d1-a9c1-0000f80367c1 (userPrincipalName, User-Principal-Name)
=================================
GUID: 4b6e08c0-df3c-11d1-9c86-006008764d0e
Name: msmq-Receive-Dead-Letter
Display Name: Receive Dead Letter
Applies To:
	9a0dc344-c100-11d1-bbc5-0080c76670c0 (mSMQConfiguration, MSMQ-Configuration)
=================================
GUID: 4b6e08c1-df3c-11d1-9c86-006008764d0e
Name: msmq-Peek-Dead-Letter
Display Name: Peek Dead Letter
Applies To:
	9a0dc344-c100-11d1-bbc5-0080c76670c0 (mSMQConfiguration, MSMQ-Configuration)
=================================
GUID: 4b6e08c2-df3c-11d1-9c86-006008764d0e
Name: msmq-Receive-computer-Journal
Display Name: Receive Computer Journal
Applies To:
	9a0dc344-c100-11d1-bbc5-0080c76670c0 (mSMQConfiguration, MSMQ-Configuration)
=================================
GUID: 4b6e08c3-df3c-11d1-9c86-006008764d0e
Name: msmq-Peek-computer-Journal
Display Name: Peek Computer Journal
Applies To:
	9a0dc344-c100-11d1-bbc5-0080c76670c0 (mSMQConfiguration, MSMQ-Configuration)
=================================
GUID: 06bd3200-df3e-11d1-9c86-006008764d0e
Name: msmq-Receive
Display Name: Receive Message
Applies To:
	9a0dc343-c100-11d1-bbc5-0080c76670c0 (mSMQQueue, MSMQ-Queue)
=================================
GUID: 06bd3201-df3e-11d1-9c86-006008764d0e
Name: msmq-Peek
Display Name: Peek Message
Applies To:
	9a0dc343-c100-11d1-bbc5-0080c76670c0 (mSMQQueue, MSMQ-Queue)
=================================
GUID: 06bd3202-df3e-11d1-9c86-006008764d0e
Name: msmq-Send
Display Name: Send Message
Applies To:
	46b27aac-aafa-4ffb-b773-e5bf621ee87b (msMQ-Group, MSMQ-Group)
	9a0dc343-c100-11d1-bbc5-0080c76670c0 (mSMQQueue, MSMQ-Queue)
=================================
GUID: 06bd3203-df3e-11d1-9c86-006008764d0e
Name: msmq-Receive-journal
Display Name: Receive Journal
Applies To:
	9a0dc343-c100-11d1-bbc5-0080c76670c0 (mSMQQueue, MSMQ-Queue)
=================================
GUID: b4e60130-df3f-11d1-9c86-006008764d0e
Name: msmq-Open-Connector
Display Name: Open Connector Queue
Applies To:
	bf967ab3-0de6-11d0-a285-00aa003049e2 (site, Site)
=================================
GUID: edacfd8f-ffb3-11d1-b41d-00a0c968f939
Name: Apply-Group-Policy
Display Name: Apply Group Policy
Applies To:
	f30e3bc2-9ff0-11d1-b603-0000f80367c1 (groupPolicyContainer, Group-Policy-Container)
=================================
GUID: 037088f8-0ae1-11d2-b422-00a0c968f939
Name: RAS-Information
Display Name: Remote Access Information
Applies To:
	4828cc14-1437-45bc-9b07-ad6f015e5f28 (inetOrgPerson, Represents people who are associated with an organization in some way.)
	bf967aba-0de6-11d0-a285-00aa003049e2 (user, User)
Consists Of:
	65650576-4699-4fc9-8d18-26e0cd0137a6 (msds-tokenGroupNames, The distinguished names of security groups the principal is directly or indirectly a member of.)
	fa06d1f4-7922-4aad-b79c-b2201f54417c (msds-tokenGroupNamesGlobalAndUniversal, The distinguished names of global and universal security groups the principal is directly or indirectly a member of.)
	523fc6c8-9af4-4a02-9cd7-3dea129eeb27 (msds-tokenGroupNamesNoGCAcceptable, The distinguished names of security groups the principal is directly or indirectly a member of as reported by the local DC.)
	db0c9085-c1f2-11d1-bbc5-0080c76670c0 (msNPAllowDialin, msNPAllowDialin)
	db0c908a-c1f2-11d1-bbc5-0080c76670c0 (msNPCallingStationID, msNPCallingStationID)
	db0c909c-c1f2-11d1-bbc5-0080c76670c0 (msRADIUSCallbackNumber, msRADIUSCallbackNumber)
	db0c90a4-c1f2-11d1-bbc5-0080c76670c0 (msRADIUSFramedIPAddress, msRADIUSFramedIPAddress)
	db0c90a9-c1f2-11d1-bbc5-0080c76670c0 (msRADIUSFramedRoute, msRADIUSFramedRoute)
	db0c90b6-c1f2-11d1-bbc5-0080c76670c0 (msRADIUSServiceType, msRADIUSServiceType)
	b7c69e6d-2cc7-11d2-854e-00a0c983f608 (tokenGroups, Token-Groups)
	46a9b11d-60ae-405a-b7e8-ff8a58d456d2 (tokenGroupsGlobalAndUniversal, Token-Groups-Global-And-Universal)
	040fc392-33df-11d2-98b2-0000f87a57d4 (tokenGroupsNoGCAcceptable, Token-Groups-No-GC-Acceptable)
=================================
GUID: 9923a32a-3607-11d2-b9be-0000f87a36b2
Name: DS-Install-Replica
Display Name: Add/Remove Replica In Domain
Applies To:
	19195a5b-6da0-11d0-afd3-00c04fd930c9 (domainDNS, Domain-DNS)
=================================
GUID: cc17b1fb-33d9-11d2-97d4-00c04fd8d5cd
Name: Change-Infrastructure-Master
Display Name: Change Infrastructure Master
Applies To:
	2df90d89-009f-11d2-aa4c-00c04fd7d83a (infrastructureUpdate, Infrastructure-Update)
=================================
GUID: be2bb760-7f46-11d2-b9ad-00c04f79f805
Name: Update-Schema-Cache
Display Name: Update Schema Cache
Applies To:
	bf967a8f-0de6-11d0-a285-00aa003049e2 (dMD, DMD)
=================================
GUID: 62dd28a8-7f46-11d2-b9ad-00c04f79f805
Name: Recalculate-Security-Inheritance
Display Name: Recalculate Security Inheritance
Applies To:
	f0f8ffab-1191-11d0-a060-00aa006c33ed (nTDSDSA, NTDS-DSA)
=================================
GUID: 69ae6200-7f46-11d2-b9ad-00c04f79f805
Name: DS-Check-Stale-Phantoms
Display Name: Check Stale Phantoms
Applies To:
	f0f8ffab-1191-11d0-a060-00aa006c33ed (nTDSDSA, NTDS-DSA)
=================================
GUID: 0e10c968-78fb-11d2-90d4-00c04f79dc55
Name: Certificate-Enrollment
Display Name: Enroll
Applies To:
	e5209ca2-3bba-11d2-90cc-00c04fd91ab1 (pKICertificateTemplate, PKI-Certificate-Template)
=================================
GUID: bf9679c0-0de6-11d0-a285-00aa003049e2
Name: Self-Membership
Display Name: Add/Remove self as member
Applies To:
	bf967a9c-0de6-11d0-a285-00aa003049e2 (group, Group)
=================================
GUID: 72e39547-7b18-11d1-adef-00c04fd8d5cd
Name: Validated-DNS-Host-Name
Display Name: Validated write to DNS host name
Applies To:
	7b8b558a-93a5-4af7-adca-c017e67f1057 (msDS-GroupManagedServiceAccount, The group managed service account class is used to create an account which can be shared by different computers to run Windows services.)
	ce206244-5827-4a86-ba1c-1c0c386c1b64 (msDS-ManagedServiceAccount, Service account class is used to create accounts that are used for running Windows services.)
	bf967a86-0de6-11d0-a285-00aa003049e2 (computer, Computer)
Consists Of:
	72e39547-7b18-11d1-adef-00c04fd8d5cd (dNSHostName, DNS-Host-Name)
	80863791-dbe9-4eb8-837e-7f0ab55d9ac7 (msDS-AdditionalDnsHostName, ms-DS-Additional-Dns-Host-Name)
=================================
GUID: f3a64788-5306-11d1-a9c5-0000f80367c1
Name: Validated-SPN
Display Name: Validated write to service principal name
Applies To:
	7b8b558a-93a5-4af7-adca-c017e67f1057 (msDS-GroupManagedServiceAccount, The group managed service account class is used to create an account which can be shared by different computers to run Windows services.)
	ce206244-5827-4a86-ba1c-1c0c386c1b64 (msDS-ManagedServiceAccount, Service account class is used to create accounts that are used for running Windows services.)
	bf967a86-0de6-11d0-a285-00aa003049e2 (computer, Computer)
=================================
GUID: b7b1b3dd-ab09-4242-9e30-9980e5d322f7
Name: Generate-RSoP-Planning
Display Name: Generate Resultant Set of Policy (Planning)
Applies To:
	19195a5b-6da0-11d0-afd3-00c04fd930c9 (domainDNS, Domain-DNS)
	bf967aa5-0de6-11d0-a285-00aa003049e2 (organizationalUnit, Organizational-Unit)
=================================
GUID: 9432c620-033c-4db7-8b58-14ef6d0bf477
Name: Refresh-Group-Cache
Display Name: Refresh Group Cache for Logons
Applies To:
	f0f8ffab-1191-11d0-a060-00aa006c33ed (nTDSDSA, NTDS-DSA)
=================================
GUID: 91d67418-0135-4acc-8d79-c08e857cfbec
Name: SAM-Enumerate-Entire-Domain
Display Name: Enumerate Entire SAM Domain
Applies To:
	bf967aad-0de6-11d0-a285-00aa003049e2 (samServer, Sam-Server)
=================================
GUID: b7b1b3de-ab09-4242-9e30-9980e5d322f7
Name: Generate-RSoP-Logging
Display Name: Generate Resultant Set of Policy (Logging)
Applies To:
	19195a5b-6da0-11d0-afd3-00c04fd930c9 (domainDNS, Domain-DNS)
	bf967aa5-0de6-11d0-a285-00aa003049e2 (organizationalUnit, Organizational-Unit)
=================================
GUID: b8119fd0-04f6-4762-ab7a-4986c76b3f9a
Name: Domain-Other-Parameters
Display Name: Other Domain Parameters (for use by SAM)
Applies To:
	19195a5b-6da0-11d0-afd3-00c04fd930c9 (domainDNS, Domain-DNS)
Consists Of:
	bf96795e-0de6-11d0-a285-00aa003049e2 (domainReplica, Domain-Replica)
	bf967977-0de6-11d0-a285-00aa003049e2 (forceLogoff, Force-Logoff)
	bf9679c5-0de6-11d0-a285-00aa003049e2 (modifiedCount, Modified-Count)
	bf9679ea-0de6-11d0-a285-00aa003049e2 (oEMInformation, OEM-Information)
	bf967a33-0de6-11d0-a285-00aa003049e2 (serverRole, Server-Role)
	bf967a34-0de6-11d0-a285-00aa003049e2 (serverState, Server-State)
	bf967a61-0de6-11d0-a285-00aa003049e2 (uASCompat, UAS-Compat)
=================================
GUID: 72e39547-7b18-11d1-adef-00c04fd8d5cd
Name: DNS-Host-Name-Attributes
Display Name: DNS Host Name Attributes
Applies To:
	7b8b558a-93a5-4af7-adca-c017e67f1057 (msDS-GroupManagedServiceAccount, The group managed service account class is used to create an account which can be shared by different computers to run Windows services.)
	ce206244-5827-4a86-ba1c-1c0c386c1b64 (msDS-ManagedServiceAccount, Service account class is used to create accounts that are used for running Windows services.)
	bf967a86-0de6-11d0-a285-00aa003049e2 (computer, Computer)
Consists Of:
	72e39547-7b18-11d1-adef-00c04fd8d5cd (dNSHostName, DNS-Host-Name)
	80863791-dbe9-4eb8-837e-7f0ab55d9ac7 (msDS-AdditionalDnsHostName, ms-DS-Additional-Dns-Host-Name)
=================================
GUID: e2a36dc9-ae17-47c3-b58b-be34c55ba633
Name: Create-Inbound-Forest-Trust
Display Name: Create Inbound Forest Trust
Applies To:
	19195a5b-6da0-11d0-afd3-00c04fd930c9 (domainDNS, Domain-DNS)
=================================
GUID: 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2
Name: DS-Replication-Get-Changes-All
Display Name: Replicating Directory Changes All
Applies To:
	bf967a8f-0de6-11d0-a285-00aa003049e2 (dMD, DMD)
	bf967a87-0de6-11d0-a285-00aa003049e2 (configuration, Configuration)
	19195a5b-6da0-11d0-afd3-00c04fd930c9 (domainDNS, Domain-DNS)
=================================
GUID: ba33815a-4f93-4c76-87f3-57574bff8109
Name: Migrate-SID-History
Display Name: Migrate SID History
Applies To:
	19195a5b-6da0-11d0-afd3-00c04fd930c9 (domainDNS, Domain-DNS)
=================================
GUID: 45ec5156-db7e-47bb-b53f-dbeb2d03c40f
Name: Reanimate-Tombstones
Display Name: Reanimate Tombstones
Applies To:
	bf967a8f-0de6-11d0-a285-00aa003049e2 (dMD, DMD)
	bf967a87-0de6-11d0-a285-00aa003049e2 (configuration, Configuration)
	19195a5b-6da0-11d0-afd3-00c04fd930c9 (domainDNS, Domain-DNS)
=================================
GUID: 68b1d179-0d15-4d4f-ab71-46152e79a7bc
Name: Allowed-To-Authenticate
Display Name: Allowed to Authenticate
Applies To:
	7b8b558a-93a5-4af7-adca-c017e67f1057 (msDS-GroupManagedServiceAccount, The group managed service account class is used to create an account which can be shared by different computers to run Windows services.)
	4828cc14-1437-45bc-9b07-ad6f015e5f28 (inetOrgPerson, Represents people who are associated with an organization in some way.)
	bf967aba-0de6-11d0-a285-00aa003049e2 (user, User)
	ce206244-5827-4a86-ba1c-1c0c386c1b64 (msDS-ManagedServiceAccount, Service account class is used to create accounts that are used for running Windows services.)
	bf967a86-0de6-11d0-a285-00aa003049e2 (computer, Computer)
=================================
GUID: 2f16c4a5-b98e-432c-952a-cb388ba33f2e
Name: DS-Execute-Intentions-Script
Display Name: Execute Forest Update Script
Applies To:
	ef9e60e0-56f7-11d1-a9c6-0000f80367c1 (crossRefContainer, Cross-Ref-Container)
=================================
GUID: f98340fb-7c5b-4cdb-a00b-2ebdfa115a96
Name: DS-Replication-Monitor-Topology
Display Name: Monitor Active Directory Replication
Applies To:
	bf967a8f-0de6-11d0-a285-00aa003049e2 (dMD, DMD)
	bf967a87-0de6-11d0-a285-00aa003049e2 (configuration, Configuration)
	19195a5b-6da0-11d0-afd3-00c04fd930c9 (domainDNS, Domain-DNS)
=================================
GUID: 280f369c-67c7-438e-ae98-1d46f3c6f541
Name: Update-Password-Not-Required-Bit
Display Name: Update Password Not Required Bit
Applies To:
	19195a5b-6da0-11d0-afd3-00c04fd930c9 (domainDNS, Domain-DNS)
=================================
GUID: ccc2dc7d-a6ad-4a7a-8846-c04e3cc53501
Name: Unexpire-Password
Display Name: Unexpire Password
Applies To:
	19195a5b-6da0-11d0-afd3-00c04fd930c9 (domainDNS, Domain-DNS)
=================================
GUID: 05c74c5e-4deb-43b4-bd9f-86664c2a7fd5
Name: Enable-Per-User-Reversibly-Encrypted-Password
Display Name: Enable Per User Reversibly Encrypted Password
Applies To:
	19195a5b-6da0-11d0-afd3-00c04fd930c9 (domainDNS, Domain-DNS)
=================================
GUID: 4ecc03fe-ffc0-4947-b630-eb672a8a9dbc
Name: DS-Query-Self-Quota
Display Name: Query Self Quota
Applies To:
	da83fc4f-076f-4aea-b4dc-8f4dab9b5993 (msDS-QuotaContainer, A special container that holds all quota specifications for the directory database.)
=================================
GUID: 91e647de-d96f-4b70-9557-d63ff4f3ccd8
Name: Private-Information
Display Name: Private Information
Applies To:
	bf967aba-0de6-11d0-a285-00aa003049e2 (user, User)
	4828cc14-1437-45bc-9b07-ad6f015e5f28 (inetOrgPerson, Represents people who are associated with an organization in some way.)
Consists Of:
	b7ff5a38-0818-42b0-8110-d3d154c97f24 (msPKI-CredentialRoamingTokens, Storage of encrypted user credential token blobs for roaming.)
	6617e4ac-a2f1-43ab-b60c-11fbd1facf05 (msPKIRoamingTimeStamp, Time stamp for last change to roaming tokens)
	b3f93023-9239-4f7c-b99c-6745d87adbc2 (msPKIDPAPIMasterKeys, Storage of encrypted DPAPI Master Keys for user)
	b8dfa744-31dc-4ef1-ac7c-84baf7ef9da7 (msPKIAccountCredentials, Storage of encrypted user credential token blobs for roaming)
=================================
GUID: 1131f6ae-9c07-11d1-f79f-00c04fc2dcd2
Name: Read-Only-Replication-Secret-Synchronization
Display Name: Read Only Replication Secret Synchronization
Applies To:
	bf967a8f-0de6-11d0-a285-00aa003049e2 (dMD, DMD)
	bf967a87-0de6-11d0-a285-00aa003049e2 (configuration, Configuration)
	19195a5b-6da0-11d0-afd3-00c04fd930c9 (domainDNS, Domain-DNS)
=================================
GUID: ffa6f046-ca4b-4feb-b40d-04dfee722543
Name: MS-TS-GatewayAccess
Display Name: MS-TS-GatewayAccess
Applies To:
	7b8b558a-93a5-4af7-adca-c017e67f1057 (msDS-GroupManagedServiceAccount, The group managed service account class is used to create an account which can be shared by different computers to run Windows services.)
	ce206244-5827-4a86-ba1c-1c0c386c1b64 (msDS-ManagedServiceAccount, Service account class is used to create accounts that are used for running Windows services.)
	bf967a86-0de6-11d0-a285-00aa003049e2 (computer, Computer)
=================================
GUID: 5805bc62-bdc9-4428-a5e2-856a0f4c185e
Name: Terminal-Server-License-Server
Display Name: Terminal Server License Server
Applies To:
	bf967aba-0de6-11d0-a285-00aa003049e2 (user, User)
	4828cc14-1437-45bc-9b07-ad6f015e5f28 (inetOrgPerson, Represents people who are associated with an organization in some way.)
Consists Of:
	6db69a1c-9422-11d1-aebd-0000f80367c1 (terminalServer, Terminal-Server)
	70004ef5-25c3-446a-97c8-996ae8566776 (msTSExpireDate, TS Expiration Date)
	54dfcf71-bc3f-4f0b-9d5a-4b2476bb8925 (msTSExpireDate2, Expiration date of the second TS per user CAL.)
	41bc7f04-be72-4930-bd10-1f3439412387 (msTSExpireDate3, Expiration date of the third TS per user CAL.)
	5e11dc43-204a-4faf-a008-6863621c6f5f (msTSExpireDate4, Expiration date of the fourth TS per user CAL.)
	0ae94a89-372f-4df2-ae8a-c64a2bc47278 (msTSLicenseVersion, TS License Version)
	4b0df103-8d97-45d9-ad69-85c3080ba4e7 (msTSLicenseVersion2, Version of the second TS per user CAL.)
	f8ba8f81-4cab-4973-a3c8-3a6da62a5e31 (msTSLicenseVersion3, Version of the third TS per user CAL.)
	70ca5d97-2304-490a-8a27-52678c8d2095 (msTSLicenseVersion4, Version of the fourth TS per user CAL.)
	f3bcc547-85b0-432c-9ac0-304506bf2c83 (msTSManagingLS, TS Managing License Server)
	349f0757-51bd-4fc8-9d66-3eceea8a25be (msTSManagingLS2, Issuer name of the second TS per user CAL.)
	fad5dcc1-2130-4c87-a118-75322cd67050 (msTSManagingLS3, Issuer name of the third TS per user CAL.)
	f7a3b6a0-2107-4140-b306-75cb521731e5 (msTSManagingLS4, Issuer name of the fourth TS per user CAL.)
=================================
GUID: 1a60ea8d-58a6-4b20-bcdc-fb71eb8a9ff8
Name: Reload-SSL-Certificate
Display Name: Reload SSL/TLS Certificate
Applies To:
	f0f8ffab-1191-11d0-a060-00aa006c33ed (nTDSDSA, NTDS-DSA)
=================================
GUID: 89e95b76-444d-4c62-991a-0facbeda640c
Name: DS-Replication-Get-Changes-In-Filtered-Set
Display Name: Replicating Directory Changes In Filtered Set
Applies To:
	bf967a8f-0de6-11d0-a285-00aa003049e2 (dMD, DMD)
	bf967a87-0de6-11d0-a285-00aa003049e2 (configuration, Configuration)
	19195a5b-6da0-11d0-afd3-00c04fd930c9 (domainDNS, Domain-DNS)
=================================
GUID: 7726b9d5-a4b4-4288-a6b2-dce952e80a7f
Name: Run-Protect-Admin-Groups-Task
Display Name: Run Protect Admin Groups Task
Applies To:
	19195a5b-6da0-11d0-afd3-00c04fd930c9 (domainDNS, Domain-DNS)
=================================
GUID: 7c0e2a7c-a419-48e4-a995-10180aad54dd
Name: Manage-Optional-Features
Display Name: Manage Optional Features for Active Directory
Applies To:
	ef9e60e0-56f7-11d1-a9c6-0000f80367c1 (crossRefContainer, Cross-Ref-Container)
=================================
GUID: 3e0f7e18-2c7a-4c10-ba82-4d926db99a3e
Name: DS-Clone-Domain-Controller
Display Name: Allow a DC to create a clone of itself
Applies To:
	19195a5b-6da0-11d0-afd3-00c04fd930c9 (domainDNS, Domain-DNS)
=================================
GUID: d31a8757-2447-4545-8081-3bb610cacbf2
Name: Validated-MS-DS-Behavior-Version
Display Name: Validated write to MS DS behavior version
Applies To:
	f0f8ffab-1191-11d0-a060-00aa006c33ed (nTDSDSA, NTDS-DSA)
=================================
GUID: 80863791-dbe9-4eb8-837e-7f0ab55d9ac7
Name: Validated-MS-DS-Additional-DNS-Host-Name
Display Name: Validated write to MS DS Additional DNS Host Name
Applies To:
	bf967a86-0de6-11d0-a285-00aa003049e2 (computer, Computer)
=================================
GUID: a05b8cc2-17bc-4802-a710-e7c15ab866a2
Name: Certificate-AutoEnrollment
Display Name: AutoEnrollment
Applies To:
	e5209ca2-3bba-11d2-90cc-00c04fd91ab1 (pKICertificateTemplate, PKI-Certificate-Template)
=================================
GUID: 4125c71f-7fac-4ff0-bcb7-f09a41325286
Name: DS-Set-Owner
Display Name: Set Owner of an object during creation.
Applies To:
	26f11b08-a29d-4869-99bb-ef0b99fd883e (UNKNOWN GUID)
=================================
GUID: 88a9933e-e5c8-4f2a-9dd7-2527416b8092
Name: DS-Bypass-Quota
Display Name: Bypass the quota restrictions during creation.
Applies To:
	26f11b08-a29d-4869-99bb-ef0b99fd883e (UNKNOWN GUID)
=================================
GUID: 084c93a2-620d-4879-a836-f0ae47de0e89
Name: DS-Read-Partition-Secrets
Display Name: Read secret attributes of objects in a Partition.
Applies To:
	26f11b08-a29d-4869-99bb-ef0b99fd883e (UNKNOWN GUID)
=================================
GUID: 94825a8d-b171-4116-8146-1e34d8f54401
Name: DS-Write-Partition-Secrets
Display Name: Write secret attributes of objects in a Partition.
Applies To:
	26f11b08-a29d-4869-99bb-ef0b99fd883e (UNKNOWN GUID)
=================================
GUID: 9b026da6-0d3c-465c-8bee-5199d7165cba
Name: DS-Validated-Write-Computer
Display Name: Validated write to computer attributes.
Applies To:
	bf967a86-0de6-11d0-a285-00aa003049e2 (computer, Computer)
Consists Of:
	5b47d60f-6090-40b2-9f37-2a4de88f3063 (msDS-KeyCredentialLink, Contains key material and usage.)
```

</details>

# License
(c) 2024, Yury Strozhevsky
[yury@strozhevsky.com](mailto:yury@strozhevsky.com)

Anyone allowed to do whatever he/she want with the code.