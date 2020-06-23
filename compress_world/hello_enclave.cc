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
#include "compress_world/hello_compression.pb.h"

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

#include "zlib.h"

class HelloApplication : public asylo::TrustedApplication {

 public:
  HelloApplication() : visitor_count_(0) {}

  asylo::Status Run(const asylo::EnclaveInput &input,
                    asylo::EnclaveOutput *output) override {
    if (!input.HasExtension(compress_world::enclave_input_hello)) {
      return asylo::Status(asylo::error::GoogleError::INVALID_ARGUMENT,
                           "Expected a HelloInput extension on input.");
    }

    std::string visitor =
        input.GetExtension(compress_world::enclave_input_hello).to_greet();
	unsigned long nCompressedDataSize = visitor.length();
	unsigned char *pCompressedData = (unsigned char *)visitor.c_str();

	// decompress
	unsigned long nDataSize = 265;
	unsigned char * pUncompressedData = new unsigned char [nDataSize];
	int nResult = uncompress(pUncompressedData, &nDataSize, pCompressedData, nCompressedDataSize);

	if (nResult != Z_OK) {
        LOG(INFO) << "DeCompression failed " << nResult << "\n" ;
        LOG(INFO) << "DeCompression orig " << nCompressedDataSize << " bytes --> " << nDataSize << " bytes\n" ;
	} else {
        LOG(INFO) << "DeCompression succeed " << nResult << "\n" ;
        LOG(INFO) << "DeCompression orig " << nCompressedDataSize << " bytes --> " << nDataSize << " bytes\n" ;
        LOG(INFO) << "orig " << pCompressedData << " --> " << pUncompressedData << "\n" ;
	}
	std::string out_((char *)pUncompressedData);	

	std::string out = 
		absl::StrCat("Hello ", out_ , "! You are visitor #",
                           ++visitor_count_, " to this enclave.");
	size_t source_size = out.length();

    if (output) {

      output->MutableExtension(compress_world::enclave_output_hello)
          ->set_greeting_message(out);
    }
    return asylo::Status::OkStatus();
  }

 private:
  uint64_t visitor_count_;
};

namespace asylo {

TrustedApplication *BuildTrustedApplication() { return new HelloApplication; }

}  // namespace asylo
