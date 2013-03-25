#pragma once

#define COPY_ARRAY(dst, src, len) { \
		struct { \
			uint8_t _[len]; \
		} *_src, *_dst; \
		_src = (void*)src; \
		_dst = (void*)dst; \
		*_dst = *_src; \
	}
