# Copyright 2018 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################

FROM gcr.io/oss-fuzz-base/base-builder
RUN apt-get update && apt-get install -y make libtool pkg-config
RUN git clone --recursive --depth 1 git://git.ghostscript.com/mupdf.git mupdf
RUN git clone --depth 1 https://github.com/mozilla/pdf.js pdf.js && \
    zip -q $SRC/pdf_fuzzer_seed_corpus.zip pdf.js/test/pdfs/*.pdf && \
    rm -rf pdf.js
RUN git clone https://github.com/jsummers/bmpsuite.git bmpsuite && \
    make -C bmpsuite && \
    zip -q -u $SRC/pdf_fuzzer_seed_corpus.zip bmpsuite/?/* && \
    rm -rf bmpsuite
RUN wget -r -p -nc -np --level=0 https://sembiance.com/fileFormatSamples/image/pbm/ && \
    zip -q -u $SRC/pdf_fuzzer_seed_corpus.zip sembiance.com/fileFormatSamples/image/pbm/* && \
    rm -rf sembiance.com/fileFormatSamples/image/pbm
RUN wget -r -p -nc -np --level=0 https://sembiance.com/fileFormatSamples/image/pgm/ && \
    zip -q -u $SRC/pdf_fuzzer_seed_corpus.zip sembiance.com/fileFormatSamples/image/pgm/* && \
    rm -rf sembiance.com/fileFormatSamples/image/pgm
RUN wget -r -p -nc -np --level=0 https://sembiance.com/fileFormatSamples/image/ppm/ && \
    zip -q -u $SRC/pdf_fuzzer_seed_corpus.zip sembiance.com/fileFormatSamples/image/ppm/* && \
    rm -rf sembiance.com/fileFormatSamples/image/ppm
RUN wget -r -p -nc -np --level=0 https://sembiance.com/fileFormatSamples/image/pfm/ && \
    zip -q -u $SRC/pdf_fuzzer_seed_corpus.zip sembiance.com/fileFormatSamples/image/pfm/* && \
    rm -rf sembiance.com/fileFormatSamples/image/pfm
RUN wget -r -p -nc -np --level=0 https://sembiance.com/fileFormatSamples/image/png/ && \
    zip -q -u $SRC/pdf_fuzzer_seed_corpus.zip sembiance.com/fileFormatSamples/image/png/* && \
    rm -rf sembiance.com/fileFormatSamples/image/png
RUN wget -r -p -nc -np --level=0 https://sembiance.com/fileFormatSamples/image/jpg/ && \
    zip -q -u $SRC/pdf_fuzzer_seed_corpus.zip sembiance.com/fileFormatSamples/image/jpg/* && \
    rm -rf sembiance.com/fileFormatSamples/image/jpg
RUN wget -r -p -nc -np --level=0 https://sembiance.com/fileFormatSamples/image/jpeg2000/ && \
    zip -q -u $SRC/pdf_fuzzer_seed_corpus.zip sembiance.com/fileFormatSamples/image/jpeg2000/* && \
    rm -rf sembiance.com/fileFormatSamples/image/jpeg2000
RUN wget -r -p -nc -np --level=0 https://sembiance.com/fileFormatSamples/image/jpegXR/ && \
    zip -q -u $SRC/pdf_fuzzer_seed_corpus.zip sembiance.com/fileFormatSamples/image/jpegXR/* && \
    rm -rf sembiance.com/fileFormatSamples/image/jpegXR
RUN wget -r -p -nc -np --level=0 https://sembiance.com/fileFormatSamples/image/jpegXR/ && \
    zip -q -u $SRC/pdf_fuzzer_seed_corpus.zip sembiance.com/fileFormatSamples/image/jpegXR/* && \
    rm -rf sembiance.com/fileFormatSamples/image/jpegXR
RUN wget -r -p -nc -np --level=0 https://sembiance.com/fileFormatSamples/image/gif/ && \
    zip -q -u $SRC/pdf_fuzzer_seed_corpus.zip sembiance.com/fileFormatSamples/image/gif/* && \
    rm -rf sembiance.com/fileFormatSamples/image/gif
RUN wget -r -p -nc -np --level=0 https://sembiance.com/fileFormatSamples/image/tiff/ && \
    zip -q -u $SRC/pdf_fuzzer_seed_corpus.zip sembiance.com/fileFormatSamples/image/tiff/* && \
    rm -rf sembiance.com/fileFormatSamples/image/tiff
RUN wget -r -p -nc -np --level=0 https://sembiance.com/fileFormatSamples/image/psd/ && \
    zip -q -u $SRC/pdf_fuzzer_seed_corpus.zip sembiance.com/fileFormatSamples/image/psd/* && \
    rm -rf sembiance.com/fileFormatSamples/image/psd
RUN wget -r -p -nc -np --level=0 https://sembiance.com/fileFormatSamples/image/svg/ && \
    zip -q -u $SRC/pdf_fuzzer_seed_corpus.zip sembiance.com/fileFormatSamples/image/svg/* && \
    rm -rf sembiance.com/fileFormatSamples/image/svg
ADD https://raw.githubusercontent.com/rc0r/afl-fuzz/master/dictionaries/pdf.dict $SRC/pdf_fuzzer.dict
WORKDIR mupdf
COPY *.cc $SRC/
COPY build.sh *.options $SRC/
