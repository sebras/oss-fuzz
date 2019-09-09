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
MAINTAINER sebastian.rasmussen@artifex.com
RUN apt-get update && apt-get install -y make libtool pkg-config vim libreadline-dev
RUN git clone --recursive --depth 1 git://git.ghostscript.com/mujs.git mujs
RUN git clone --depth 1 https://github.com/tc39/test262.git test262 && \
    zip -q $SRC/js_fuzzer_seed_corpus.zip test262/test/**/*.js && \
    rm -rf test262
ADD https://raw.githubusercontent.com/rc0r/afl-fuzz/master/dictionaries/js.dict $SRC/js_fuzzer.dict
WORKDIR mujs
COPY *.cc $SRC/
COPY build.sh *.options $SRC/
