/* Licenses and Notices
1.	Copyright Licenses:

    Trusted Computing Group (TCG) grants to the user of the source code in
    this specification (the "Source Code") a worldwide, irrevocable, nonexclusive,
    royalty free, copyright license to reproduce, create derivative works,
    distribute, display and perform the Source Code and derivative works
    thereof, and to grant others the rights granted herein.

    The TCG grants to the user of the other parts of the specification
    (other than the Source Code) the rights to reproduce, distribute,
    display, and perform the specification solely for the purpose of
    developing products based on such documents.
    
2.	Source Code Distribution Conditions:

    Redistributions of Source Code must retain the above copyright licenses,
    this list of conditions and the following disclaimers.
    
	Redistributions in binary form must reproduce the above copyright
    licenses, this list of conditions and the following disclaimers in
    the documentation and/or other materials provided with the distribution.
    
3.	Disclaimers:

    THE COPYRIGHT LICENSES SET FORTH ABOVE DO NOT REPRESENT ANY FORM OF LICENSE
    OR WAIVER, EXPRESS OR IMPLIED, BY ESTOPPEL OR OTHERWISE, WITH RESPECT TO
    PATENT RIGHTS HELD BY TCG MEMBERS (OR OTHER THIRD PARTIES) THAT MAY BE NECESSARY
    TO IMPLEMENT THIS SPECIFICATION OR OTHERWISE. Contact TCG Administration
    (admin@trustedcomputinggroup.org) for information on specification licensing
    rights available through TCG membership agreements.
    
	THIS SPECIFICATION IS PROVIDED "AS IS" WITH NO EXPRESS OR IMPLIED WARRANTIES
    WHATSOEVER, INCLUDING ANY WARRANTY OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR
    PURPOSE, ACCURACY, COMPLETENESS, OR NONINFRINGEMENT OF INTELLECTUAL PROPERTY
    RIGHTS, OR ANY WARRANTY OTHERWISE ARISING OUT OF ANY PROPOSAL, SPECIFICATION
    OR SAMPLE.

    Without limitation, TCG and its members and licensors disclaim all liability,
    including liability for infringement of any proprietary rights, relating to
    use of information in this specification and to the implementation of this
    specification, and TCG disclaims all liability for cost of procurement of
    substitute goods or services, lost profits, loss of use, loss of data or any
    incidental, consequential, direct, indirect, or special damages, whether
    under contract, tort, warranty or otherwise, arising in any way out of use
    or reliance upon this specification or any information herein.
    
Any marks and brands contained herein are the property of their respective owner.
*/

// 5.2	BaseTypes.h

/* rev 119 */

#ifndef TSS2_API_VERSION_1_1_1_1
#error Version mismatch among TSS2 header files !
#endif  /* TSS2_API_VERSION_1_1_1_1 */

#ifndef _BASETYPES_H
#define _BASETYPES_H

#include "stdint.h"

// NULL definition
#ifndef         NULL
#define         NULL        (0)
#endif

typedef uint8_t		UINT8;		/* unsigned, 8-bit integer */
typedef uint8_t		BYTE;		/* unsigned 8-bit integer */
typedef int8_t		INT8;		/* signed, 8-bit integer */
typedef int		BOOL;		/* a bit in an int  */
typedef uint16_t	UINT16;		/* unsigned, 16-bit integer */
typedef int16_t		INT16;		/* signed, 16-bit integer */
typedef uint32_t	UINT32;		/* unsigned, 32-bit integer */
typedef int32_t		INT32;		/* signed, 32-bit integer */
typedef uint64_t	UINT64;		/* unsigned, 64-bit integer */
typedef int64_t		INT64;		/* signed, 64-bit integer */

typedef struct {
    UINT16        size;
    BYTE          buffer[1];
} TPM2B;

#endif
