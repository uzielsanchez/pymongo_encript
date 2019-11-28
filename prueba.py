connection_string = URI_CONNECTION

#connection_string = "mongodb://localhost:27017"
key_vault_namespace = "encryption.__keyVault"

client = MongoClient(connection_string)
client_encryption = ClientEncryption(

    kms_providers, # pass in the kms_providers variable from the previous step

    key_vault_namespace,
    client,
    CodecOptions(uuid_representation=STANDARD)
)


def create_data_encryption_key():

    data_key_id = client_encryption.create_data_key("local")

    uuid_data_key_id = UUID(bytes=data_key_id)
    base_64_data_key_id = base64.b64encode(data_key_id)
    print("DataKeyId [UUID]: ", str(uuid_data_key_id))
    print("DataKeyId [base64]: ", base_64_data_key_id)
    return data_key_id


data_key_id = create_data_encryption_key()

key_vault_db = "encryption"
key_vault_coll = "__keyVault"


client = MongoClient(connection_string)
key_vault = client[key_vault_db][key_vault_coll]	

# Pass in the data_key_id created in previous section
key = key_vault.find_one({"_id": data_key_id})
pprint(key)

def bson_schema_creator(data_key_id):
	return  {
  "bsonType": "object",
  "encryptMetadata": {
    "keyId": [
      {
        "$binary": {
          "base64": data_key_id,
          "subType": "04"
        }
      }
    ]
  },
  "properties": {
    "insurance": {
      "bsonType": "object",
      "properties": {
        "policyNumber": {
          "encrypt": {
            "bsonType": "int",
            "algorithm": "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"
          }
        }
      }
    },
    "medicalRecords": {
      "encrypt": {
        "bsonType": "array",
        "algorithm": "AEAD_AES_256_CBC_HMAC_SHA_512-Random"
      }
    },
    "bloodType": {
      "encrypt": {
        "bsonType": "string",
        "algorithm": "AEAD_AES_256_CBC_HMAC_SHA_512-Random"
      }
    },
    "ssn": {
      "encrypt": {
        "bsonType": "int",
        "algorithm": "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"
      }
    }
  }
}

kms_providers = {

  "local": {

    "key": local_master_key

  }
}

json_schema = bson_schema_creator(data_key_id)

patient_schema = {

  "medicalRecords.patients": json_schema

}

extra_options = {

   'mongocryptd_spawn_path': '/usr/local/bin/mongocryptd'

}

# or  extra_options['mongocryptd_bypass_spawn'] = True


fle_opts = AutoEncryptionOpts(

   kms_providers,

   key_vault_namespace,

   schema_map=patient_schema,

   **extra_options

)
client = MongoClient(connection_string, auto_encryption_opts=fle_opts)

#key_vault_db = "encryption"
#key_vault_coll = "__keyVault"
#client = MongoClient(connection_string)
#key_vault = client[key_vault_db][key_vault_coll]
#coleccion_vault = client[base_encriptada][coleccion]



base_encriptada = "base_encriptada"
coleccion = "coleccion_encriptada"
coleccion_base = client[base_encriptada][coleccion]

def insert_patient(base_coleccion, name, ssn, blood_type, medical_records, policy_number, provider):
  insurance = {
    'policyNumber': policy_number,
    'provider': provider
  }
  doc = {
      'name': name,
      'ssn': ssn,
      'bloodType': blood_type,
      'medicalRecords': medical_records,
      'insurance': insurance
  }
  base_coleccion.insert_one(doc)

insert_patient(coleccion_base, "Uziel", 34568346, "O", "jghejgh", 3453485356, "GNP")
