#include <iostream>
#include <map>
#include <vector>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <regex>
#include <cwctype>

#include <Windows.h>
#include <dsgetdc.h>
#include <winldap.h>
#include <winber.h>
#include <LM.h>

#pragma comment(lib, "NetApi32.lib")
#pragma comment(lib, "Wldap32.lib")
//****************************************************************************************************
using _ldap_unbind = decltype([](LDAP* value){ ldap_unbind(value); });
using _ldap_msgfree = decltype([](LDAPMessage* value){ ldap_msgfree(value); });
using _ldap_memfree = decltype([](PWCHAR value){ ldap_memfreeW(value); });
using _ldap_value_free = decltype([](PWCHAR* value){ ldap_value_freeW(value); });
using _ldap_value_free_len = decltype([](berval** value){ ldap_value_free_len(value); });

struct _ldap_search_abandon_page
{
	PLDAP _ldap_handle;
	void operator()(PLDAPSearch value) const noexcept { ldap_search_abandon_page(_ldap_handle, value); };
};

using _NetApiBufferFree = decltype([](PDOMAIN_CONTROLLER_INFOW value){ NetApiBufferFree(value); });
using _ber_free = decltype([](BerElement* value){ ber_free(value, 0); });
//****************************************************************************************************
std::string hex_codes(std::vector<unsigned char> value)
{
	std::stringstream stream;
	stream << std::uppercase << std::setfill('0') << std::hex;
	std::for_each(value.begin(), value.end(), [&stream](unsigned char element){ stream << std::setw(2) << (int)element; });

	return stream.str();
}
//****************************************************************************************************
std::string guid_to_string(std::vector<unsigned char> value)
{
	#pragma region Initial variables
	std::string hex = hex_codes(value);

	std::stringstream stream;

	std::regex regex("([0-9a-fA-F]{8})-{0,1}([0-9a-fA-F]{4})([0-9a-fA-F]{4})([0-9a-fA-F]{4})([0-9a-fA-F]{12})");
	std::match_results<std::string::const_iterator> match;
	#pragma endregion

	#pragma region Check input string format
	if(false == std::regex_match(hex, match, regex))
		throw std::exception("GUID: invalid Value");
	#pragma endregion

	#pragma region Parse input string
	for(size_t i = 1; i < 6; i++)
	{
		size_t index = 0;

		std::string value = match[i];
		std::vector<std::string> chunks(value.size() >> 1, std::string{ 2, ' ' });

		for(auto j = value.begin(); j != value.end(); j += 2)
			std::copy_n(j, 2, chunks[index++].begin());

		if(i < 4)
			std::reverse(chunks.begin(), chunks.end());

		if((size_t)stream.tellp())
			stream << "-";

		std::copy(chunks.begin(), chunks.end(), std::ostream_iterator<std::string, char>(stream));
	}
	#pragma endregion

	return stream.str();
}
//****************************************************************************************************
void extendedRightsLDAP()
{
	#pragma region Initial variables
	std::map<std::string, std::pair<std::string, std::string>> schemaAttributes;
	std::multimap<std::string, std::string> securityGUIDToGUID;

	LDAP_TIMEVAL tm{ .tv_sec = 1000, .tv_usec = 1000 };
	unsigned long pageSize = 100;
	unsigned long pageTimeLimit = 100000;
	unsigned long entryCount;
	unsigned long errorCode = LDAP_SUCCESS;
	#pragma endregion

	#pragma region Aux lambda
	auto displaySchemaAttribute = [&schemaAttributes](std::string value)
	{
		auto guid_search = schemaAttributes.find(value);
		if(guid_search != schemaAttributes.end())
			std::cout << '\t' << value << " (" << (*guid_search).second.first << ", " << (*guid_search).second.second << ")" << std::endl;
		else
			std::cout << '\t' << value << " (UNKNOWN GUID)" << std::endl;
	};

	auto error = [](std::string_view info){ std::cout << "Error: " << info << std::endl; };
	#pragma endregion

	#pragma region Initialize connection with LDAP server
	#pragma region Get information about LDAP server name
	std::unique_ptr<DOMAIN_CONTROLLER_INFOW, _NetApiBufferFree> inflow;

	auto result = DsGetDcNameW(nullptr, nullptr, nullptr, nullptr, DS_ONLY_LDAP_NEEDED | DS_RETURN_DNS_NAME, std::out_ptr(inflow));
	if(nullptr == inflow)
		return error("Cannot find LDAP server with DsGetDcNameW");
	#pragma endregion

	#pragma region Initialize TLS connection with LDAP server
	std::unique_ptr<LDAP, _ldap_unbind> ldap_handle{ ldap_sslinitW(&inflow->DomainControllerName[2], LDAP_SSL_PORT, 1) };
	if(nullptr == ldap_handle)
		return error("Cannot initialize TLS LDAP connection");

	#pragma region Set additional options for LDAP connection
	if(ldap_set_optionW(ldap_handle.get(), LDAP_OPT_AREC_EXCLUSIVE, LDAP_OPT_ON))
		return error("Cannot set LDAP_OPT_AREC_EXCLUSIVE option");

	ULONG ldap_version = LDAP_VERSION3;
	if(ldap_set_optionW(ldap_handle.get(), LDAP_OPT_PROTOCOL_VERSION, &ldap_version))
		return error("Cannot set LDAP_OPT_PROTOCOL_VERSION option");
	#pragma endregion

	if(ldap_bind_sW(ldap_handle.get(), nullptr, nullptr, LDAP_AUTH_NEGOTIATE))
		return error("Cannot bind to LDAP connection with current credentials");
	#pragma endregion
	#pragma endregion

	#pragma region Get information about "Configuration" and "Schema" namespaces
	#pragma region Search for all namingContexts
	const wchar_t* namingContexts[] = {
		L"namingContexts",
		nullptr
	};

	std::unique_ptr<LDAPMessage, _ldap_msgfree> namingContextsMessage;
	if(ldap_search_sW(ldap_handle.get(), (wchar_t*)L"", LDAP_SCOPE_BASE, (wchar_t*)L"(objectCategory=*)", (wchar_t**)namingContexts, FALSE, std::out_ptr(namingContextsMessage)))
		return error("Cannot perform search for namingContexts");
	#pragma endregion

	#pragma region Get values from the search
	auto namingContextsEntry = ldap_first_entry(ldap_handle.get(), namingContextsMessage.get());
	if(nullptr == namingContextsEntry)
		return error("ldap_first_entry returns empty entry");

	std::unique_ptr<BerElement, _ber_free> namingContextsBER;

	std::unique_ptr<wchar_t, _ldap_memfree> namingContextsAttribute{ ldap_first_attributeW(ldap_handle.get(), namingContextsEntry, std::out_ptr(namingContextsBER)) };
	if(nullptr == namingContextsAttribute)
		return error("ldap_first_attributeW returns emtpy attribute");

	std::unique_ptr<wchar_t* [], _ldap_value_free> namingContextsValues{ ldap_get_valuesW(ldap_handle.get(), namingContextsEntry, namingContextsAttribute.get()) };
	if(nullptr == namingContextsValues)
		return error("Cannot get values for namingContexts");

	auto namingContextsValuesCount = ldap_count_valuesW(namingContextsValues.get());
	#pragma endregion

	#pragma region Find correct DN names for necessary namespaces
	std::wstring config_ns;
	std::wstring schema_ns;

	for(ULONG i = 0; i < namingContextsValuesCount; i++)
	{
		std::wstring value{ namingContextsValues[i] };
		std::transform(value.begin(), value.end(), value.begin(), std::towlower);

		if(value.find(L"cn=configuration") == 0)
			config_ns = std::move(value);
		else
		{
			if(value.find(L"cn=schema") == 0)
				schema_ns = std::move(value);
		}

		if(config_ns.size() && schema_ns.size())
			break;
	}

	if(!(config_ns.size() && schema_ns.size()))
		return;
	#pragma endregion
	#pragma endregion

	#pragma region Get information about all attributes from "Schema" namespace
	{
		const wchar_t* schemaAttrs[] = {
			L"ldapDisplayName",
			L"adminDescription",
			L"attributeSecurityGUID",
			L"schemaIdGuid",
			nullptr
		};

		std::unique_ptr<LDAPSearch, decltype(_ldap_search_abandon_page(ldap_handle.get()))> page_handle{
			ldap_search_init_pageW(
				ldap_handle.get(),
				schema_ns.data(),
				LDAP_SCOPE_SUBTREE,
				(PWSTR)L"schemaIdGuid=*",
				(PZPWSTR)schemaAttrs,
				0,
				nullptr,
				nullptr,
				pageTimeLimit,
				pageSize,
				nullptr
			)
		};
		if(nullptr == page_handle)
			return error("Cannot get search page results (Schema namespace)");

		do
		{
			std::unique_ptr<LDAPMessage, _ldap_msgfree> search_message;

			errorCode = ldap_get_next_page_s(
				ldap_handle.get(),
				page_handle.get(),
				&tm,
				pageSize,
				&entryCount,
				std::out_ptr(search_message)
			);
			if(search_message)
			{
				auto search_entry = ldap_first_entry(ldap_handle.get(), search_message.get());

				while(nullptr != search_entry)
				{
					#pragma region Get all necessary values
					std::unique_ptr<berval* [], _ldap_value_free_len> ldapDisplayNameValues{ ldap_get_values_lenW(ldap_handle.get(), search_entry, (PWSTR)schemaAttrs[0]) };
					if(!ldapDisplayNameValues)
						return error("Cannot get values for ldapDisplayName");

					std::string adminDescriptionString;

					std::unique_ptr<berval* [], _ldap_value_free_len> adminDescriptionValues{ ldap_get_values_lenW(ldap_handle.get(), search_entry, (PWSTR)schemaAttrs[1]) };
					if(adminDescriptionValues)
						adminDescriptionString = adminDescriptionValues[0]->bv_val;
					else
						adminDescriptionString = ldapDisplayNameValues[0]->bv_val;

					std::string security_guid_str;

					std::unique_ptr<berval* [], _ldap_value_free_len> attributeSecurityGUID{ ldap_get_values_lenW(ldap_handle.get(), search_entry, (PWSTR)schemaAttrs[2]) };
					if(attributeSecurityGUID)
					{
						security_guid_str = guid_to_string({ attributeSecurityGUID[0]->bv_val, attributeSecurityGUID[0]->bv_val + attributeSecurityGUID[0]->bv_len });
						std::transform(security_guid_str.begin(), security_guid_str.end(), security_guid_str.begin(), tolower);
					}

					std::unique_ptr<berval* [], _ldap_value_free_len> schemaIdGuidValues{ ldap_get_values_lenW(ldap_handle.get(), search_entry, (PWSTR)schemaAttrs[3]) };
					if(!schemaIdGuidValues)
						return error("Cannot get values for schemaIdGuid");

					std::string guid_str = guid_to_string({ schemaIdGuidValues[0]->bv_val, schemaIdGuidValues[0]->bv_val + schemaIdGuidValues[0]->bv_len });
					std::transform(guid_str.begin(), guid_str.end(), guid_str.begin(), tolower);
					#pragma endregion

					#pragma region Store all values to map
					schemaAttributes[guid_str] = std::make_pair(ldapDisplayNameValues[0]->bv_val, adminDescriptionString);

					if(security_guid_str.size())
						securityGUIDToGUID.emplace(std::make_pair(security_guid_str, guid_str));
					#pragma endregion

					search_entry = ldap_next_entry(ldap_handle.get(), search_entry);
				}
			}
		} while(errorCode == LDAP_SUCCESS);
	}
	#pragma endregion

	#pragma region Get information about all extended access rights from "Configuration" namespace
	{
		const wchar_t* configAttrs[] = {
			L"name",
			L"displayName",
			L"appliesTo",
			L"rightsGuid",
			nullptr
		};

		std::unique_ptr<LDAPSearch, decltype(_ldap_search_abandon_page(ldap_handle.get()))> page_handle{
			ldap_search_init_pageW(
				ldap_handle.get(),
				config_ns.data(),
				LDAP_SCOPE_SUBTREE,
				(PWSTR)L"rightsGuid=*",
				(PZPWSTR)configAttrs,
				0,
				nullptr,
				nullptr,
				pageTimeLimit,
				pageSize,
				nullptr
			)
		};
		if(nullptr == page_handle)
			return error("Cannot get search page results (Configuration namespace)");

		do
		{
			std::unique_ptr<LDAPMessage, _ldap_msgfree> search_message;

			errorCode = ldap_get_next_page_s(
				ldap_handle.get(),
				page_handle.get(),
				&tm,
				pageSize,
				&entryCount,
				std::out_ptr(search_message)
			);
			if(search_message)
			{
				auto search_entry = ldap_first_entry(ldap_handle.get(), search_message.get());

				while(nullptr != search_entry)
				{
					#pragma region Get all necessary values
					std::unique_ptr<berval* [], _ldap_value_free_len> nameValues{ ldap_get_values_lenW(ldap_handle.get(), search_entry, (PWSTR)configAttrs[0]) };
					if(!nameValues)
						return error("Cannot get values for name");

					std::unique_ptr<berval* [], _ldap_value_free_len> displayNameValues{ ldap_get_values_lenW(ldap_handle.get(), search_entry, (PWSTR)configAttrs[1]) };
					if(!displayNameValues)
						return error("Cannot get values for displayName");

					std::unique_ptr<berval* [], _ldap_value_free_len> appliesToValues{ ldap_get_values_lenW(ldap_handle.get(), search_entry, (PWSTR)configAttrs[2]) };
					if(!appliesToValues)
						return error("Cannot get values for appliesTo");

					std::unique_ptr<berval* [], _ldap_value_free_len> rightsGuidValues{ ldap_get_values_lenW(ldap_handle.get(), search_entry, (PWSTR)configAttrs[3]) };
					if(!rightsGuidValues)
						return error("Cannot get values for rightsGuid");

					std::string guid_str = rightsGuidValues[0]->bv_val;
					std::transform(guid_str.begin(), guid_str.end(), guid_str.begin(), tolower);
					#pragma endregion

					#pragma region Display information
					std::cout << "=================================" << std::endl;
					std::cout << "GUID: " << guid_str << std::endl;
					std::cout << "Name: " << nameValues[0]->bv_val << std::endl;
					std::cout << "Display Name: " << displayNameValues[0]->bv_val << std::endl;

					std::cout << "Applies To:" << std::endl;

					int i = 0;
					while(nullptr != appliesToValues[i])
					{
						std::string applies_guid_str{ appliesToValues[i++]->bv_val };
						std::transform(applies_guid_str.begin(), applies_guid_str.end(), applies_guid_str.begin(), tolower);

						displaySchemaAttribute(applies_guid_str);
					}

					#pragma region Display "Consists Of" if needed
					auto begin = securityGUIDToGUID.lower_bound(guid_str);
					auto end = securityGUIDToGUID.upper_bound(guid_str);

					if(begin != end)
					{
						std::cout << "Consists Of:" << std::endl;

						while(begin != end)
							displaySchemaAttribute((*(begin++)).second);
					}
					#pragma endregion
					#pragma endregion

					search_entry = ldap_next_entry(ldap_handle.get(), search_entry);
				}
			}
		} while(errorCode == LDAP_SUCCESS);
	}
	#pragma endregion
}
//****************************************************************************************************
int wmain(int argc, wchar_t* argv[])
{
	extendedRightsLDAP();

	return 0;
}
//****************************************************************************************************