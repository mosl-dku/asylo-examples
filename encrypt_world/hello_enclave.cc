/*
 *
 * Copyright 2018 Asylo authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "absl/base/macros.h"
#include "absl/strings/str_cat.h"
#include "asylo/trusted_application.h"
#include "asylo/util/logging.h"
#include "asylo/util/status.h"
#include "asylo/util/status_macros.h"
#include "encrypt_world/hello_enc.pb.h"

#include "absl/strings/str_cat.h"
#include "asylo/crypto/aead_cryptor.h"
#include "asylo/crypto/util/bssl_util.h"
#include "asylo/crypto/util/byte_container_view.h"
#include "asylo/crypto/util/trivial_object_util.h"
#include "asylo/util/cleansing_types.h"
#include "asylo/util/cleanup.h"
#include "asylo/util/posix_error_space.h"

#include "asylo/platform/host_call/trusted/host_calls.h"
#include "asylo/platform/posix/memory/memory.h"
#include "asylo/platform/primitives/trusted_primitives.h"
#include "asylo/platform/primitives/trusted_runtime.h"

const char AssociateDataBuf[] = "AES256-GCM-SIV encryption";
const size_t KeySize = 32;

class HelloApplication : public asylo::TrustedApplication {

 public:
  HelloApplication() : visitor_count_(0) {}

  asylo::Status Run(const asylo::EnclaveInput &input,
                    asylo::EnclaveOutput *output) override {
    if (!input.HasExtension(encrypt_world::enclave_input_hello)) {
      return asylo::Status(asylo::error::GoogleError::INVALID_ARGUMENT,
                           "Expected a HelloInput extension on input.");
    }

    std::string visitor =
        input.GetExtension(encrypt_world::enclave_input_hello).to_greet();

	std::string out_plain = 
		absl::StrCat("Hello ", visitor, "! You are visitor #",
                           ++visitor_count_, " to this enclave.");
	size_t source_size = out_plain.length();
    LOG(INFO) << "plaintext(" << source_size << "):\n" << out_plain;

	asylo::CleansingVector<uint8_t> key(KeySize);
	std::unique_ptr<asylo::AeadCryptor> cryptor;
	ASYLO_ASSIGN_OR_RETURN(cryptor,
					asylo::AeadCryptor::CreateAesGcmCryptor(key));

	std::vector<uint8_t> nonce(cryptor->NonceSize());
	size_t nonce_size = cryptor->NonceSize();
	size_t max_ciphertext_size;
	void *ciphertext;

	max_ciphertext_size = source_size + cryptor->MaxSealOverhead();
	ciphertext = asylo::primitives::TrustedPrimitives::UntrustedLocalAlloc(max_ciphertext_size);
	asylo::ByteContainerView associated_data(AssociateDataBuf, sizeof(AssociateDataBuf));
	size_t ciphertext_size;
	cryptor->Seal(out_plain, associated_data,
				absl::MakeSpan(nonce),
				absl::MakeSpan(reinterpret_cast<uint8_t *>(ciphertext), max_ciphertext_size),
				&ciphertext_size);

	std::string out_cipher((char *)ciphertext);
	//uint8_t *out_cipher = (uint8_t *)ciphertext;
    LOG(INFO) << "ciphertext(" << ciphertext_size << "):\n" << out_cipher;

    if (output) {
/*
      output->MutableExtension(encrypt_world::enclave_output_hello)
          ->set_greeting_message(out_plain);
*/
      output->MutableExtension(encrypt_world::enclave_output_hello)
          ->set_greeting_message(ciphertext, ciphertext_size);
    }
    return asylo::Status::OkStatus();
  }

 private:
  uint64_t visitor_count_;
};

namespace asylo {

TrustedApplication *BuildTrustedApplication() { return new HelloApplication; }

}  // namespace asylo
