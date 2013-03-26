#pragma once

#define ARRAY_COPY(dst, src, len) { \
		struct { \
			uint8_t _[len]; \
		} *_src, *_dst; \
		_src = (void*)src; \
		_dst = (void*)dst; \
		*_dst = *_src; \
	}
#define ARRAY_LEN(a) ((sizeof (a)) / (sizeof *(a)))
