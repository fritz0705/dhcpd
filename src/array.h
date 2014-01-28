#pragma once

#ifndef DHCPD_ARRAY_H_
#define DHCPD_ARRAY_H_

#define ARRAY_COPY(dst, src, len) { \
		struct { \
			uint8_t _[(len)]; \
		} *(_src), *(_dst); \
		(_src) = (void*)(src); \
		(_dst) = (void*)(dst); \
		*(_dst) = *(_src); \
	}
#define ARRAY_LEN(a) ((sizeof (a)) / (sizeof *(a)))

#define ARRAY_SAFE_COPY(dst, src) (ARRAY_COPY(dst, src, \
	(ARRAY_LEN(dst) > ARRAY_LEN(src) ? ARRAY_LEN(src) : ARRAY_LEN(dst))))

#endif
