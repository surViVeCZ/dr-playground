from pandas import DataFrame

import schema

nontraining_fields = [
    "domain_name",
    "dns_evaluated_on",
    "rdap_evaluated_on",
    "tls_evaluated_on",

    # IP data
    "ip_data",
    "countries",
    "latitudes",
    "longitudes",

    # DNS
    "dns_dnssec",
    "dns_email_extras",
    "dns_ttls",
    "dns_zone",
    "dns_zone_SOA",
    *[f"dns_{t}" for t in schema.dns_types_all],

    "rdap_registration_date",
    "rdap_last_changed_date",
    "rdap_expiration_date",
    "rdap_dnssec",
    "rdap_entities"

    #"tls_root_cert_validity_remaining",
    #"tls_leaf_cert_validity_remaining"
]


def drop_nontrain_table(table):
    """
    Drop non-training columns.
    """
    return table.drop(nontraining_fields)


def drop_nontrain_df(df: DataFrame) -> DataFrame:
    """
    Drop non-training columns.
    """
    df.drop(columns=nontraining_fields, inplace=True)
    return df
