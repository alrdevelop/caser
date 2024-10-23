#ifndef _CASERV_CONTRACTS_PAGEDRESPONSE_H_
#define _CASERV_CONTRACTS_PAGEDRESPONSE_H_

namespace contracts {
    
    template <typename T>
    class PagedResponse {
        public:
            const T Data;
            const long currentPage;
            const long pageSize;
            const long totalRecords;
    };
    
} // contracts
#endif //_CASERV_CONTRACTS_PAGEDRESPONSE_H_
