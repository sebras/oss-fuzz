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
    zip $SRC/pdf_fuzzer_seed_corpus.zip pdf.js/test/pdfs/*.pdf && \
    rm -rf pdf.js
RUN git clone https://github.com/jsummers/bmpsuite.git bmpsuite && \
    make -C bmpsuite && \
    zip -u $SRC/pdf_fuzzer_seed_corpus.zip bmpsuite/?/* && \
    rm -rf bmpsuite
RUN wget -P sembiance \
	https://sembiance.com/fileFormatSamples/image/gif/89aillus.gif \
	https://sembiance.com/fileFormatSamples/image/gif/062669.gif \
	https://sembiance.com/fileFormatSamples/image/gif/athome.gif \
	https://sembiance.com/fileFormatSamples/image/gif/PCtipsblank.gif \
	https://sembiance.com/fileFormatSamples/image/gif/input.gif87 \
	https://sembiance.com/fileFormatSamples/image/gif/congrats.gif \
	https://sembiance.com/fileFormatSamples/image/gif/animated.gif \
	https://sembiance.com/fileFormatSamples/image/gif/aol.gif \
	https://sembiance.com/fileFormatSamples/image/gif/wfpc04.gif \
	https://sembiance.com/fileFormatSamples/image/gif/butts09.gif \
	https://sembiance.com/fileFormatSamples/image/jpeg2000/input.j2k \
	https://sembiance.com/fileFormatSamples/image/jpg/input.jpg \
	https://sembiance.com/fileFormatSamples/image/jpg/input_plane.jpg \
	https://sembiance.com/fileFormatSamples/image/jpg/image5.jpg \
	https://sembiance.com/fileFormatSamples/image/jpg/greet02.jpg \
	https://sembiance.com/fileFormatSamples/image/jpg/thinskin.jpg \
	https://sembiance.com/fileFormatSamples/image/jpg/parrots.jpg \
	https://sembiance.com/fileFormatSamples/image/jpg/ring_mo4.jpg \
	https://sembiance.com/fileFormatSamples/image/jpg/TESTcmyk.jpg \
	https://sembiance.com/fileFormatSamples/image/jpg/example_small.jpg \
	https://sembiance.com/fileFormatSamples/image/jpg/example.jps \
	https://sembiance.com/fileFormatSamples/image/pbm/PAT_9.pbm \
	https://sembiance.com/fileFormatSamples/image/pbm/input_p4.pbm \
	https://sembiance.com/fileFormatSamples/image/pbm/input_p1.pbm \
	https://sembiance.com/fileFormatSamples/image/pbm/BMAP_3684.pbm \
	https://sembiance.com/fileFormatSamples/image/pbm/abydos.pbm \
	https://sembiance.com/fileFormatSamples/image/pfm/memorial.pfm \
	https://sembiance.com/fileFormatSamples/image/pgm/align_c.ppm \
	https://sembiance.com/fileFormatSamples/image/pgm/input_p2.pgm \
	https://sembiance.com/fileFormatSamples/image/png/input_bw.png \
	https://sembiance.com/fileFormatSamples/image/png/input_mono.png \
	https://sembiance.com/fileFormatSamples/image/png/input_16.png \
	https://sembiance.com/fileFormatSamples/image/png/input_256.png \
	https://sembiance.com/fileFormatSamples/image/png/input_truecolor.png \
	https://sembiance.com/fileFormatSamples/image/png/arrowdwn.png \
	https://sembiance.com/fileFormatSamples/image/png/JUDGE.png \
	https://sembiance.com/fileFormatSamples/image/png/diagram.png \
	https://sembiance.com/fileFormatSamples/image/png/env.raw \
	https://sembiance.com/fileFormatSamples/image/png/antiqhvy.png \
	https://sembiance.com/fileFormatSamples/image/ppm/BARNICO3.PPM \
	https://sembiance.com/fileFormatSamples/image/ppm/input_p3.ppm \
	https://sembiance.com/fileFormatSamples/image/ppm/lighthouse_rgb48.ppm \
	https://sembiance.com/fileFormatSamples/image/psd/input.psd \
	https://sembiance.com/fileFormatSamples/image/psd/Horn.psd \
	https://sembiance.com/fileFormatSamples/image/psd/derriere.psd \
	https://sembiance.com/fileFormatSamples/image/psd/Tour.psd \
	https://sembiance.com/fileFormatSamples/image/svg/abydos.smil.svg \
	https://sembiance.com/fileFormatSamples/image/svg/abydos.svg \
	https://sembiance.com/fileFormatSamples/image/svg/p17_aj.svg \
	https://sembiance.com/fileFormatSamples/image/svg/test.svg \
	https://sembiance.com/fileFormatSamples/image/svg/example.svg \
	https://sembiance.com/fileFormatSamples/image/tiff/cmap-blue-red.tif \
	https://sembiance.com/fileFormatSamples/image/tiff/input_mono.tiff \
	https://sembiance.com/fileFormatSamples/image/tiff/input_gray_4bit.tiff \
	https://sembiance.com/fileFormatSamples/image/tiff/input_16.tiff \
	https://sembiance.com/fileFormatSamples/image/tiff/input_16_matte.tiff \
	https://sembiance.com/fileFormatSamples/image/tiff/missing.tif \
	https://sembiance.com/fileFormatSamples/image/tiff/input_gray_8bit.tiff \
	https://sembiance.com/fileFormatSamples/image/tiff/input_gray_4bit_matte.tiff \
	https://sembiance.com/fileFormatSamples/image/tiff/input_256_matte.tiff \
	https://sembiance.com/fileFormatSamples/image/tiff/shiro02.tif \
	https://sembiance.com/fileFormatSamples/image/tiff/TRAIN3.TIF \
	https://sembiance.com/fileFormatSamples/image/tiff/PIE01.TIF \
	https://sembiance.com/fileFormatSamples/image/tiff/fax2d.tif \
	https://sembiance.com/fileFormatSamples/image/tiff/ccitt_4.tif \
	https://sembiance.com/fileFormatSamples/image/tiff/xing_t24.tif \
	https://sembiance.com/fileFormatSamples/image/tiff/g31d.tif \
	https://sembiance.com/fileFormatSamples/image/tiff/contract.aci \
	https://sembiance.com/fileFormatSamples/image/tiff/old-style-jpeg-compression.tif \
	https://sembiance.com/fileFormatSamples/image/tiff/Report_0001.aci \
	https://sembiance.com/fileFormatSamples/image/tiff/abydos.tiff \
	https://sembiance.com/fileFormatSamples/image/jpeg2000/LIGHT-ROM%201%20%28Amiga%20Library%20Services%29%281994%29%20Insert_0000.jp2 \
	https://sembiance.com/fileFormatSamples/document/xps/zan%201-1.xps \
	&& \
    zip -u $SRC/pdf_fuzzer_seed_corpus.zip sembiance/* && \
    rm -rf sembiance
ADD https://raw.githubusercontent.com/rc0r/afl-fuzz/master/dictionaries/pdf.dict $SRC/pdf_fuzzer.dict
WORKDIR mupdf
COPY *.cc $SRC/
COPY build.sh *.options $SRC/
