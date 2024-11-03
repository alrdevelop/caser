#ifndef _CASERV_COMMON_PAGEDRESPONSE_H_
#define _CASERV_COMMON_PAGEDRESPONSE_H_

template <typename T> class PagedResponse {
public:
  const T Data;
  const long currentPage;
  const long pageSize;
  const long totalRecords;
};
#endif //_CASERV_COMMON_PAGEDRESPONSE_H_
