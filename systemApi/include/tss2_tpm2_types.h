/********************************************************************************/
/*										*/
/*			     				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*            $Id: TPM_Types.h 192 2015-03-30 20:05:03Z kgoldman $		*/
/*										*/
/*  Licenses and Notices							*/
/*										*/
/*  1. Copyright Licenses:							*/
/*										*/
/*  - Trusted Computing Group (TCG) grants to the user of the source code in	*/
/*    this specification (the "Source Code") a worldwide, irrevocable, 		*/
/*    nonexclusive, royalty free, copyright license to reproduce, create 	*/
/*    derivative works, distribute, display and perform the Source Code and	*/
/*    derivative works thereof, and to grant others the rights granted herein.	*/
/*										*/
/*  - The TCG grants to the user of the other parts of the specification 	*/
/*    (other than the Source Code) the rights to reproduce, distribute, 	*/
/*    display, and perform the specification solely for the purpose of 		*/
/*    developing products based on such documents.				*/
/*										*/
/*  2. Source Code Distribution Conditions:					*/
/*										*/
/*  - Redistributions of Source Code must retain the above copyright licenses, 	*/
/*    this list of conditions and the following disclaimers.			*/
/*										*/
/*  - Redistributions in binary form must reproduce the above copyright 	*/
/*    licenses, this list of conditions	and the following disclaimers in the 	*/
/*    documentation and/or other materials provided with the distribution.	*/
/*										*/
/*  3. Disclaimers:								*/
/*										*/
/*  - THE COPYRIGHT LICENSES SET FORTH ABOVE DO NOT REPRESENT ANY FORM OF	*/
/*  LICENSE OR WAIVER, EXPRESS OR IMPLIED, BY ESTOPPEL OR OTHERWISE, WITH	*/
/*  RESPECT TO PATENT RIGHTS HELD BY TCG MEMBERS (OR OTHER THIRD PARTIES)	*/
/*  THAT MAY BE NECESSARY TO IMPLEMENT THIS SPECIFICATION OR OTHERWISE.		*/
/*  Contact TCG Administration (admin@trustedcomputinggroup.org) for 		*/
/*  information on specification licensing rights available through TCG 	*/
/*  membership agreements.							*/
/*										*/
/*  - THIS SPECIFICATION IS PROVIDED "AS IS" WITH NO EXPRESS OR IMPLIED 	*/
/*    WARRANTIES WHATSOEVER, INCLUDING ANY WARRANTY OF MERCHANTABILITY OR 	*/
/*    FITNESS FOR A PARTICULAR PURPOSE, ACCURACY, COMPLETENESS, OR 		*/
/*    NONINFRINGEMENT OF INTELLECTUAL PROPERTY RIGHTS, OR ANY WARRANTY 		*/
/*    OTHERWISE ARISING OUT OF ANY PROPOSAL, SPECIFICATION OR SAMPLE.		*/
/*										*/
/*  - Without limitation, TCG and its members and licensors disclaim all 	*/
/*    liability, including liability for infringement of any proprietary 	*/
/*    rights, relating to use of information in this specification and to the	*/
/*    implementation of this specification, and TCG disclaims all liability for	*/
/*    cost of procurement of substitute goods or services, lost profits, loss 	*/
/*    of use, loss of data or any incidental, consequential, direct, indirect, 	*/
/*    or special damages, whether under contract, tort, warranty or otherwise, 	*/
/*    arising in any way out of use or reliance upon this specification or any 	*/
/*    information herein.							*/
/*										*/
/*  (c) Copyright IBM Corp. and others, 2012-2015				*/
/*										*/
/********************************************************************************/

/* rev 121 */

#ifndef TSS2_API_VERSION_1_1_1_1
#error Version mismatch among TSS2 header files !
#endif  /* TSS2_API_VERSION_1_1_1_1 */

#ifndef TSS2_TPMS_TYPES_H
#define TSS2_TPMS_TYPES_H

#include <stdint.h>

#include "implementation.h"

/*
  The C bit field is non-portable, but the TPM specification reference implementation uses them.

  These two macros attempt to define the TPM specification bit fields for little and big endian
  machines.  There is no guarantee that either will work with a specific compiler or tool chain.  If
  not, the developer must create a custom structure.
  
  TPM_BITFIELD_LE - little endian
  TPM_BITFIELD_BE - big endian

  To access the structures as uint's for marshaling and unmarshaling, each bit field is a union with
  an integral field called 'val'.

  Yes, I know that this uses anonymous structs, but the alternative yields another level of
  deferencing, and will likely break more code.  I hope your compiler supports this recent addition
  to the standard.

  For portable code:
  
  If neither macro is defined, this header defines the structures as uint32_t.  It defines constants
  for the various bits, and can be used as:

  variable & CONSTANT		(test for set)
  !(variable & CONSTANT)	(test for clear)
  variable &= CONSTANT		(to set)
  variable |= ~CONSTANT		(to clear)

  Although the portable structures are all uint32_t, some only use the least significatt 8 bits and
  are marshalled as a uint_8t.
*/

/* Table 3 - Definition of Base Types */
/* In BaseTypes.h */

/* Table 4 - Defines for Logic Values */
// In Table 39 (Yes, NO)
/* In bool.h (TRUE, FALSE) */
#define SET	1
#define CLEAR	0

/* Part 4 5.3	Capabilities.h */

#define    MAX_CAP_DATA         (MAX_CAP_BUFFER-sizeof(TPM_CAP)-sizeof(UINT32))
#define    MAX_CAP_ALGS         (MAX_CAP_DATA/sizeof(TPMS_ALG_PROPERTY))
#define    MAX_CAP_HANDLES      (MAX_CAP_DATA/sizeof(TPM_HANDLE))
#define    MAX_CAP_CC           (MAX_CAP_DATA/sizeof(TPM_CC))
#define    MAX_TPM_PROPERTIES   (MAX_CAP_DATA/sizeof(TPMS_TAGGED_PROPERTY))
#define    MAX_PCR_PROPERTIES   (MAX_CAP_DATA/sizeof(TPMS_TAGGED_PCR_SELECT))
#define    MAX_ECC_CURVES       (MAX_CAP_DATA/sizeof(TPM_ECC_CURVE))

/* Table 5 - Definition of Types for Documentation Clarity */

typedef UINT32	TPM_ALGORITHM_ID; 	/* this is the 1.2 compatible form of the TPM_ALG_ID */
typedef UINT32	TPM_MODIFIER_INDICATOR;
typedef UINT32	TPM_AUTHORIZATION_SIZE; /* the authorizationSize parameter in a command */
typedef UINT32	TPM_PARAMETER_SIZE; 	/* the parameterSizeset parameter in a command */
typedef UINT16	TPM_KEY_SIZE; 		/* a key size in octets */
typedef UINT16	TPM_KEY_BITS; 		/* a key size in bits */

/* Table 6 - Definition of (UINT32) TPM_SPEC Constants <> */

typedef UINT32 TPM_SPEC;

#define TPM_SPEC_FAMILY		0x322E3000	/* ASCII "2.0" with null terminator */
#define TPM_SPEC_LEVEL		00		/* the level number for the specification */
#define TPM_SPEC_VERSION	121		/* the version number of the spec (01.21 * 100) */
#define TPM_SPEC_YEAR		2014		/* the year of the version */
#define TPM_SPEC_DAY_OF_YEAR	356		/* the day of the year */


/* Table 7 - Definition of (UINT32) TPM_GENERATED Constants <O> */

typedef UINT32 TPM_GENERATED;

#define TPM_GENERATED_VALUE	0xff544347	/* 0xFF 'TCG' (FF 54 43 47) */

/* Table 9 - Definition of (UINT16) TPM_ALG_ID Constants <IN/OUT, S> */

typedef UINT16 TPM_ALG_ID;

/* Table 10 - Definition of (UINT16) {ECC} TPM_ECC_CURVE Constants <IN/OUT, S> */

typedef UINT16 TPM_ECC_CURVE;

/* Table 17 - Definition of (UINT32) TPM_RC Constants (Actions) <OUT> */

typedef UINT32 TPM_RC;

#define TPM_RC_SUCCESS		0x000
#define TPM_RC_BAD_TAG		0x01E			/* defined for compatibility with TPM 1.2 */

#define RC_VER1			0x100			/* set for all format 0 response codes */

#define TPM_RC_INITIALIZE 	(RC_VER1 + 0x000)	/* TPM not initialized by TPM2_Startup or already initialized */
#define TPM_RC_FAILURE		(RC_VER1 + 0x001)	/* commands not being accepted because of a TPM failure */
#define TPM_RC_SEQUENCE		(RC_VER1 + 0x003)	/* improper use of a sequence handle */
#define TPM_RC_PRIVATE		(RC_VER1 + 0x00B)	/* not currently used */
#define TPM_RC_HMAC		(RC_VER1 + 0x019)	/* not currently used */
#define TPM_RC_DISABLED		(RC_VER1 + 0x020)	/* the command is disabled */
#define TPM_RC_EXCLUSIVE	(RC_VER1 + 0x021)	/* command failed because audit sequence required exclusivity */
#define TPM_RC_AUTH_TYPE	(RC_VER1 + 0x024)	/* authorization handle is not correct for command */
#define TPM_RC_AUTH_MISSING	(RC_VER1 + 0x025)	/* command requires an authorization session
							   for handle and it is not present. */
#define TPM_RC_POLICY		(RC_VER1 + 0x026)	/* policy Failure In Math Operation or an invalid authPolicy value */
#define TPM_RC_PCR		(RC_VER1 + 0x027)	/* PCR check fail */
#define TPM_RC_PCR_CHANGED	(RC_VER1 + 0x028)	/* PCR have changed since checked. */
#define TPM_RC_UPGRADE		(RC_VER1 + 0x02D)	/* for all commands other than
							   TPM2_FieldUpgradeData(), this code
							   indicates that the TPM is in field
							   upgrade mode */
#define TPM_RC_TOO_MANY_CONTEXTS (RC_VER1 + 0x02E)	/* context ID counter is at maximum. */
#define TPM_RC_AUTH_UNAVAILABLE	(RC_VER1 + 0x02F)	/* authValue or authPolicy is not available for selected entity. */
#define TPM_RC_REBOOT		(RC_VER1 + 0x030)	/* a _TPM_Init and Startup(CLEAR) is
							   required before the TPM can resume
							   operation. */
#define TPM_RC_UNBALANCED	(RC_VER1 + 0x031)	/* the protection algorithms (hash and
							   symmetric) are not reasonably balanced */
#define TPM_RC_COMMAND_SIZE	(RC_VER1 + 0x042)	/* command commandSize value is inconsistent
							   with contents of the command buffer */
#define TPM_RC_COMMAND_CODE	(RC_VER1 + 0x043)	/* command code not supported */
#define TPM_RC_AUTHSIZE		(RC_VER1 + 0x044)	/* the value of authorizationSize is out of range */
#define TPM_RC_AUTH_CONTEXT	(RC_VER1 + 0x045)	/* use of an authorization session with a
							   context command or another command that
							   cannot have an authorization session.*/
#define TPM_RC_NV_RANGE		(RC_VER1 + 0x046)	/* NV offset+size is out of range. */
#define TPM_RC_NV_SIZE		(RC_VER1 + 0x047)	/* Requested allocation size is larger than allowed. */
#define TPM_RC_NV_LOCKED	(RC_VER1 + 0x048)	/* NV access locked. */
#define TPM_RC_NV_AUTHORIZATION	(RC_VER1 + 0x049)	/* NV access authorization fails in command
							   actions (this failure does not affect
							   lockout.action) */
#define TPM_RC_NV_UNINITIALIZED	(RC_VER1 + 0x04A)	/* an NV Index is used before being
							   initialized or the state saved by
							   TPM2_Shutdown(STATE) could not be
							   restored */
#define TPM_RC_NV_SPACE		(RC_VER1 + 0x04B)	/* insufficient space for NV allocation */
#define TPM_RC_NV_DEFINED	(RC_VER1 + 0x04C)	/* NV Index or persistent object already defined */
#define TPM_RC_BAD_CONTEXT	(RC_VER1 + 0x050)	/* context in TPM2_ContextLoad() is not valid */
#define TPM_RC_CPHASH		(RC_VER1 + 0x051)	/* cpHash value already set or not correct for use */
#define TPM_RC_PARENT		(RC_VER1 + 0x052)	/* handle for parent is not a valid parent */
#define TPM_RC_NEEDS_TEST	(RC_VER1 + 0x053)	/* some function needs testing. */
#define TPM_RC_NO_RESULT	(RC_VER1 + 0x054)	/* returned when an internal function cannot
							   process a request due to an unspecified
							   problem. */
#define TPM_RC_SENSITIVE	(RC_VER1 + 0x055)	/* the sensitive area did not unmarshal correctly after decryption */
#define RC_MAX_FM0		(RC_VER1 + 0x07F)	/* largest version 1 code that is not a warning */

/* The codes in this group may have a value added to them to indicate the handle, session, or
   parameter to which they apply. */

#define RC_FMT1			0x080			/* This bit is SET in all format 1 response codes */

#define TPM_RC_ASYMMETRIC	(RC_FMT1 + 0x001)	/* asymmetric algorithm not supported or not correct */
#define TPM_RC_ATTRIBUTES	(RC_FMT1 + 0x002)	/* inconsistent attributes */
#define TPM_RC_HASH		(RC_FMT1 + 0x003)	/* hash algorithm not supported or not appropriate */
#define TPM_RC_VALUE		(RC_FMT1 + 0x004)	/* value is out of range or is not correct for the context */
#define TPM_RC_HIERARCHY	(RC_FMT1 + 0x005)	/* hierarchy is not enabled or is not correct for the use */
#define TPM_RC_KEY_SIZE		(RC_FMT1 + 0x007)	/* key size is not supported */
#define TPM_RC_MGF		(RC_FMT1 + 0x008)	/* mask generation function not supported */
#define TPM_RC_MODE		(RC_FMT1 + 0x009)	/* mode of operation not supported */
#define TPM_RC_TYPE		(RC_FMT1 + 0x00A)	/* the type of the value is not appropriate for the use */
#define TPM_RC_HANDLE		(RC_FMT1 + 0x00B)	/* the handle is not correct for the use */
#define TPM_RC_KDF		(RC_FMT1 + 0x00C)	/* unsupported key derivation function or
							   function not appropriate for use */
#define TPM_RC_RANGE		(RC_FMT1 + 0x00D)	/* value was out of allowed range. */
#define TPM_RC_AUTH_FAIL	(RC_FMT1 + 0x00E)	/* the authorization HMAC check failed and DA counter incremented */
#define TPM_RC_NONCE		(RC_FMT1 + 0x00F)	/* invalid nonce size */
#define TPM_RC_PP		(RC_FMT1 + 0x010)	/* authorization requires assertion of PP */
#define TPM_RC_SCHEME		(RC_FMT1 + 0x012)	/* unsupported or incompatible scheme */
#define TPM_RC_SIZE		(RC_FMT1 + 0x015)	/* structure is the wrong size */
#define TPM_RC_SYMMETRIC	(RC_FMT1 + 0x016)	/* unsupported symmetric algorithm or key
							   size, or not appropriate for instance */
#define TPM_RC_TAG		(RC_FMT1 + 0x017)	/* incorrect structure tag */
#define TPM_RC_SELECTOR		(RC_FMT1 + 0x018)	/* union selector is incorrect */
#define TPM_RC_INSUFFICIENT	(RC_FMT1 + 0x01A)	/* the TPM was unable to unmarshal a value
							   because there were not enough octets in
							   the input buffer */
#define TPM_RC_SIGNATURE	(RC_FMT1 + 0x01B)	/* the signature is not valid */
#define TPM_RC_KEY		(RC_FMT1 + 0x01C)	/* key fields are not compatible with the selected use */
#define TPM_RC_POLICY_FAIL	(RC_FMT1 + 0x01D)	/* a policy check failed */
#define TPM_RC_INTEGRITY	(RC_FMT1 + 0x01F)	/* integrity check failed */
#define TPM_RC_TICKET		(RC_FMT1 + 0x020)	/* invalid ticket */
#define TPM_RC_RESERVED_BITS	(RC_FMT1 + 0x021)	/* reserved bits not set to zero as required */
#define TPM_RC_BAD_AUTH		(RC_FMT1 + 0x022)	/* authorization failure without DA implications */
#define TPM_RC_EXPIRED		(RC_FMT1 + 0x023)	/* the policy has expired */
#define TPM_RC_POLICY_CC	(RC_FMT1 + 0x024) 	/* the commandCode in the policy is not the
							   commandCode of the command */
#define TPM_RC_BINDING		(RC_FMT1 + 0x025)	/* public and sensitive portions of an
							   object are not cryptographically bound */
#define TPM_RC_CURVE		(RC_FMT1 + 0x026)	/* curve not supported	 */
#define TPM_RC_ECC_POINT	(RC_FMT1 + 0x027)	/* point is not on the required curve. */

/* aliases for FMT1 commands when parameter number can be added */

#define TPM_RCS_VALUE		TPM_RC_VALUE
#define TPM_RCS_TYPE 		TPM_RC_TYPE
#define TPM_RCS_HANDLE 		TPM_RC_HANDLE
#define TPM_RCS_SIZE		TPM_RC_SIZE
#define TPM_RCS_ATTRIBUTES	TPM_RC_ATTRIBUTES	
#define TPM_RCS_NONCE		TPM_RC_NONCE
#define TPM_RCS_SYMMETRIC	TPM_RC_SYMMETRIC
#define TPM_RCS_MODE 		TPM_RC_MODE 
#define TPM_RCS_SCHEME		TPM_RC_SCHEME
#define TPM_RCS_KEY		TPM_RC_KEY
#define TPM_RCS_ECC_POINT	TPM_RC_ECC_POINT
#define TPM_RCS_HASH		TPM_RC_HASH
#define TPM_RCS_HIERARCHY	TPM_RC_HIERARCHY
#define TPM_RCS_TICKET		TPM_RC_TICKET
#define TPM_RCS_RANGE		TPM_RC_RANGE
#define TPM_RCS_INTEGRITY 	TPM_RC_INTEGRITY 
#define TPM_RCS_POLICY_CC	TPM_RC_POLICY_CC
#define TPM_RCS_EXPIRED		TPM_RC_EXPIRED

#define RC_WARN			0x900			/* set for warning response codes */

#define TPM_RC_CONTEXT_GAP	(RC_WARN + 0x001)	/* gap for context ID is too large */
#define TPM_RC_OBJECT_MEMORY	(RC_WARN + 0x002)	/* out of memory for object contexts */
#define TPM_RC_SESSION_MEMORY	(RC_WARN + 0x003)	/* out of memory for session contexts */
#define TPM_RC_MEMORY		(RC_WARN + 0x004)	/* out of shared object/session memory or
							   need space for internal operations */
#define TPM_RC_SESSION_HANDLES	(RC_WARN + 0x005)	/* out of session handles - a session must
							   be flushed before a new session may be
							   created */
#define TPM_RC_OBJECT_HANDLES	(RC_WARN + 0x006)	/* out of object handles - the handle space
							   for objects is depleted and a reboot is
							   required */
#define TPM_RC_LOCALITY		(RC_WARN + 0x007)	/* bad locality */
#define TPM_RC_YIELDED		(RC_WARN + 0x008)	/* the TPM has suspended operation on the
							   command; forward progress was made and
							   the command may be retried. */
#define TPM_RC_CANCELED		(RC_WARN + 0x009)	/* the command was canceled */
#define TPM_RC_CANCELLED	TPM_RC_CANCELED
#define TPM_RC_TESTING		(RC_WARN + 0x00A)	/* TPM is performing self-tests */
#define TPM_RC_REFERENCE_H0	(RC_WARN + 0x010)	/* the 1st handle in the handle area
							   references a transient object or session
							   that is not loaded */
#define TPM_RC_REFERENCE_H1	(RC_WARN + 0x011)	/* the 2nd handle in the handle area
							   references a transient object or session
							   that is not loaded */
#define TPM_RC_REFERENCE_H2	(RC_WARN + 0x012)	/* the 3rd handle in the handle area
							   references a transient object or session
							   that is not loaded */
#define TPM_RC_REFERENCE_H3	(RC_WARN + 0x013)	/* the 4th handle in the handle area
							   references a transient object or session
							   that is not loaded */
#define TPM_RC_REFERENCE_H4	(RC_WARN + 0x014)	/* the 5th handle in the handle area
							   references a transient object or session
							   that is not loaded */
#define TPM_RC_REFERENCE_H5	(RC_WARN + 0x015)	/* the 6th handle in the handle area
							   references a transient object or session
							   that is not loaded */
#define TPM_RC_REFERENCE_H6	(RC_WARN + 0x016)	/* the 7th handle in the handle area
							   references a transient object or session
							   that is not loaded */
#define TPM_RC_REFERENCE_S0	(RC_WARN + 0x018)	/* the 1st authorization session handle
							   references a session that is not
							   loaded */
#define TPM_RC_REFERENCE_S1	(RC_WARN + 0x019)	/* the 2nd authorization session handle
							   references a session that is not
							   loaded */
#define TPM_RC_REFERENCE_S2	(RC_WARN + 0x01A)	/* the 3rd authorization session handle
							   references a session that is not
							   loaded */
#define TPM_RC_REFERENCE_S3	(RC_WARN + 0x01B)	/* the 4th authorization session handle
							   references a session that is not
							   loaded */
#define TPM_RC_REFERENCE_S4	(RC_WARN + 0x01C)	/* the 5th session handle references a
							   session that is not loaded */
#define TPM_RC_REFERENCE_S5	(RC_WARN + 0x01D)	/* the 6th session handle references a session that is not loaded */
#define TPM_RC_REFERENCE_S6	(RC_WARN + 0x01E)	/* the 7th authorization session handle
							   references a session that is not
							   loaded */
#define TPM_RC_NV_RATE		(RC_WARN + 0x020)	/* the TPM is rate-limiting accesses to prevent wearout of NV */
#define TPM_RC_LOCKOUT		(RC_WARN + 0x021)	/* authorizations for objects subject to DA
							   protection are not allowed at this time
							   because the TPM is in DA lockout mode */
#define TPM_RC_RETRY		(RC_WARN + 0x022)	/* the TPM was not able to start the command */
#define TPM_RC_NV_UNAVAILABLE	(RC_WARN + 0x023)	/* the command may require writing of NV and
							   NV is not current accessible */
#define TPM_RC_NOT_USED		(RC_WARN + 0x07F)	/* this value is reserved and shall not be returned by the TPM */

#define TPM_RC_H		0x000			/* add to a handle-related error */
#define TPM_RC_P		0x040			/* add to a parameter-related error */
#define TPM_RC_S		0x800			/* add to a session-related error */
#define TPM_RC_1		0x100			/* add to a parameter-, handle-, or session-related error */
#define TPM_RC_2		0x200			/* add to a parameter-, handle-, or session-related error */
#define TPM_RC_3		0x300			/* add to a parameter-, handle-, or session-related error */
#define TPM_RC_4		0x400			/* add to a parameter-, handle-, or session-related error */
#define TPM_RC_5		0x500			/* add to a parameter-, handle-, or session-related error */
#define TPM_RC_6		0x600			/* add to a parameter-, handle-, or session-related error */
#define TPM_RC_7		0x700			/* add to a parameter-, handle-, or session-related error */
#define TPM_RC_8		0x800			/* add to a parameter-related error */
#define TPM_RC_9		0x900			/* add to a parameter-related error */
#define TPM_RC_A		0xA00			/* add to a parameter-related error */
#define TPM_RC_B		0xB00			/* add to a parameter-related error */
#define TPM_RC_C		0xC00			/* add to a parameter-related error */
#define TPM_RC_D		0xD00			/* add to a parameter-related error */
#define TPM_RC_E		0xE00			/* add to a parameter-related error */
#define TPM_RC_F		0xF00			/* add to a parameter-related error */
#define TPM_RC_N_MASK		0xF00			/* number mask */

/* Table 18 - Definition of (INT8) TPM_CLOCK_ADJUST Constants <IN> */

typedef INT8 TPM_CLOCK_ADJUST;

#define TPM_CLOCK_COARSE_SLOWER		-3	/* Slow the Clock update rate by one coarse adjustment step. */
#define TPM_CLOCK_MEDIUM_SLOWER		-2	/* Slow the Clock update rate by one medium adjustment step. */
#define TPM_CLOCK_FINE_SLOWER		-1	/* Slow the Clock update rate by one fine adjustment step. */
#define TPM_CLOCK_NO_CHANGE		0	/* No change to the Clock update rate. */
#define TPM_CLOCK_FINE_FASTER		1	/* Speed the Clock update rate by one fine adjustment step. */
#define TPM_CLOCK_MEDIUM_FASTER		2	/* Speed the Clock update rate by one medium adjustment step. */
#define TPM_CLOCK_COARSE_FASTER		3	/* Speed the Clock update rate by one coarse adjustment step. */

/* Table 19 - Definition of (UINT16) TPM_EO Constants <IN/OUT> */

typedef UINT16 TPM_EO;

#define TPM_EO_EQ		0x0000	/* A = B */
#define TPM_EO_NEQ		0x0001	/* A ? B */
#define TPM_EO_SIGNED_GT	0x0002	/* A > B signed	 */
#define TPM_EO_UNSIGNED_GT	0x0003	/* A > B unsigned	 */
#define TPM_EO_SIGNED_LT	0x0004	/* A < B signed	 */
#define TPM_EO_UNSIGNED_LT	0x0005	/* A < B unsigned	 */
#define TPM_EO_SIGNED_GE	0x0006	/* A = B signed	 */
#define TPM_EO_UNSIGNED_GE	0x0007	/* A = B unsigned	 */
#define TPM_EO_SIGNED_LE	0x0008	/* A = B signed	 */
#define TPM_EO_UNSIGNED_LE	0x0009	/* A = B unsigned	 */
#define TPM_EO_BITSET		0x000A	/* All bits SET in B are SET in A. ((A&B)=B)	 */
#define TPM_EO_BITCLEAR		0x000B	/* All bits SET in B are CLEAR in A. ((A&B)=0) */

/* Table 20 - Definition of (UINT16) TPM_ST Constants <IN/OUT, S> */

typedef UINT16 TPM_ST;

#define TPM_ST_RSP_COMMAND		0x00C4	/* tag value for a response */
#define TPM_ST_NULL			0X8000	/* no structure type specified */
#define TPM_ST_NO_SESSIONS		0x8001	/* command/response has no attached sessions*/
#define TPM_ST_SESSIONS			0x8002	/* command/response has one or more attached sessions*/
#define TPM_ST_ATTEST_NV		0x8014	/* tag for an attestation structure	 */
#define TPM_ST_ATTEST_COMMAND_AUDIT	0x8015	/* tag for an attestation structure	 */
#define TPM_ST_ATTEST_SESSION_AUDIT	0x8016	/* tag for an attestation structure	 */
#define TPM_ST_ATTEST_CERTIFY		0x8017	/* tag for an attestation structure	 */
#define TPM_ST_ATTEST_QUOTE		0x8018	/* tag for an attestation structure	 */
#define TPM_ST_ATTEST_TIME		0x8019	/* tag for an attestation structure	 */
#define TPM_ST_ATTEST_CREATION		0x801A	/* tag for an attestation structure	*/
#define TPM_ST_CREATION			0x8021	/* tag for a ticket type	 */
#define TPM_ST_VERIFIED			0x8022	/* tag for a ticket type	 */
#define TPM_ST_AUTH_SECRET		0x8023	/* tag for a ticket type	 */
#define TPM_ST_HASHCHECK		0x8024	/* tag for a ticket type	 */
#define TPM_ST_AUTH_SIGNED		0x8025	/* tag for a ticket type	 */
#define TPM_ST_FU_MANIFEST		0x8029	/* tag for a structure describing a Field Upgrade Policy */

/* Table 21 - Definition of (UINT16) TPM_SU Constants <IN> */

typedef UINT16 TPM_SU;

#define TPM_SU_CLEAR	0x0000	/* on TPM2_Startup(), indicates that the TPM should perform TPM Reset or TPM Restart */
#define TPM_SU_STATE	0x0001	/* on TPM2_Startup(), indicates that the TPM should restore the
				   state saved by TPM2_Shutdown(TPM_SU_STATE) */
/* Table 22 - Definition of (UINT8) TPM_SE Constants <IN> */

typedef UINT8 TPM_SE;

#define TPM_SE_HMAC	0x00
#define TPM_SE_POLICY	0x01
#define TPM_SE_TRIAL	0x03

/* Table 23 - Definition of (UINT32) TPM_CAP Constants  */

typedef UINT32 TPM_CAP;

#define TPM_CAP_FIRST		0x00000000	/* 		*/
#define TPM_CAP_ALGS		0x00000000	/* TPM_ALG_ID(1)	TPML_ALG_PROPERTY	*/
#define TPM_CAP_HANDLES		0x00000001	/* TPM_HANDLE		TPML_HANDLE	*/
#define TPM_CAP_COMMANDS	0x00000002	/* TPM_CC		TPML_CCA	*/
#define TPM_CAP_PP_COMMANDS	0x00000003	/* TPM_CC		TPML_CC 	*/
#define TPM_CAP_AUDIT_COMMANDS	0x00000004	/* TPM_CC		TPML_CC	*/
#define TPM_CAP_PCRS		0x00000005	/* reserved		TPML_PCR_SELECTION	*/
#define TPM_CAP_TPM_PROPERTIES	0x00000006	/* TPM_PT		TPML_TAGGED_TPM_PROPERTY	*/
#define TPM_CAP_PCR_PROPERTIES	0x00000007	/* TPM_PT_PCR		TPML_TAGGED_PCR_PROPERTY	*/
#define TPM_CAP_ECC_CURVES	0x00000008	/* TPM_ECC_CURVE(1)	TPML_ECC_CURVE	*/
#define TPM_CAP_LAST		0x00000008	/* */		
#define TPM_CAP_VENDOR_PROPERTY	0x00000100	/* manufacturer specific	manufacturer-specific values */

/* Table 24 - Definition of (UINT32) TPM_PT Constants <IN/OUT, S> */

typedef UINT32 TPM_PT;
		
#define TPM_PT_NONE	0x00000000	/* indicates no property type */
#define PT_GROUP	0x00000100	/* The number of properties in each group. */
#define PT_FIXED	(PT_GROUP * 1)	/* the group of fixed properties returned as TPMS_TAGGED_PROPERTY */

/* The values in this group are only changed due to a firmware change in the TPM. */

#define TPM_PT_FAMILY_INDICATOR		(PT_FIXED + 0)	/* a 4-octet character string containing the
							   TPM Family value (TPM_SPEC_FAMILY) */
#define TPM_PT_LEVEL			(PT_FIXED + 1)	/* the level of the specification */
#define TPM_PT_REVISION			(PT_FIXED + 2)	/* the specification Revision times 100 */
#define TPM_PT_DAY_OF_YEAR		(PT_FIXED + 3)	/* the specification day of year using TCG calendar */
#define TPM_PT_YEAR			(PT_FIXED + 4)	/* the specification year using the CE */
#define TPM_PT_MANUFACTURER		(PT_FIXED + 5)	/* the vendor ID unique to each TPM manufacturer	 */
#define TPM_PT_VENDOR_STRING_1		(PT_FIXED + 6)	/* the first four characters of the vendor ID string */
#define TPM_PT_VENDOR_STRING_2		(PT_FIXED + 7)	/* the second four characters of the vendor ID string	 */
#define TPM_PT_VENDOR_STRING_3		(PT_FIXED + 8)	/* the third four characters of the vendor ID string	 */
#define TPM_PT_VENDOR_STRING_4		(PT_FIXED + 9)	/* the fourth four characters of the vendor ID sting	 */
#define TPM_PT_VENDOR_TPM_TYPE		(PT_FIXED + 10)	/* vendor-defined value indicating the TPM model	 */
#define TPM_PT_FIRMWARE_VERSION_1	(PT_FIXED + 11)	/* the most-significant 32 bits of a TPM
							   vendor-specific value indicating the
							   version number of the firmware */
#define TPM_PT_FIRMWARE_VERSION_2	(PT_FIXED + 12)	/* the least-significant 32 bits of a TPM
							   vendor-specific value indicating the
							   version number of the firmware */
#define TPM_PT_INPUT_BUFFER		(PT_FIXED + 13)	/* the maximum size of a parameter
							   (typically, a TPM2B_MAX_BUFFER) */
#define TPM_PT_HR_TRANSIENT_MIN		(PT_FIXED + 14)	/* the minimum number of transient objects
							   that can be held in TPM RAM */
#define TPM_PT_HR_PERSISTENT_MIN	(PT_FIXED + 15)	/* the minimum number of persistent objects
							   that can be held in TPM NV memory */
#define TPM_PT_HR_LOADED_MIN		(PT_FIXED + 16)	/* the minimum number of authorization
							   sessions that can be held in TPM RAM */
#define TPM_PT_ACTIVE_SESSIONS_MAX	(PT_FIXED + 17)	/* the number of authorization sessions that
							   may be active at a time */
#define TPM_PT_PCR_COUNT		(PT_FIXED + 18)	/* the number of PCR implemented */
#define TPM_PT_PCR_SELECT_MIN		(PT_FIXED + 19)	/* the minimum number of octets in a
							   TPMS_PCR_SELECT.sizeOfSelect */
#define TPM_PT_CONTEXT_GAP_MAX		(PT_FIXED + 20)	/* the maximum allowed difference (unsigned)
							   between the contextID values of two saved
							   session contexts */
#define TPM_PT_NV_COUNTERS_MAX		(PT_FIXED + 22)	/* the maximum number of NV Indexes that are
							   allowed to have TPM_NV_COUNTER attribute SET */
#define TPM_PT_NV_INDEX_MAX		(PT_FIXED + 23)	/* the maximum size of an NV Index data area */
#define TPM_PT_MEMORY			(PT_FIXED + 24)	/* a TPMA_MEMORY indicating the memory
							   management method for the TPM */
#define TPM_PT_CLOCK_UPDATE		(PT_FIXED + 25)	/* interval, in milliseconds, between
							   updates to the copy of
							   TPMS_CLOCK_INFO.clock in NV */
#define TPM_PT_CONTEXT_HASH		(PT_FIXED + 26)	/* the algorithm used for the integrity HMAC
							   on saved contexts and for hashing the
							   fuData of TPM2_FirmwareRead() */
#define TPM_PT_CONTEXT_SYM		(PT_FIXED + 27)	/* TPM_ALG_ID, the algorithm used for
							   encryption of saved contexts */
#define TPM_PT_CONTEXT_SYM_SIZE		(PT_FIXED + 28)	/* TPM_KEY_BITS, the size of the key used
							   for encryption of saved contexts */
#define TPM_PT_ORDERLY_COUNT		(PT_FIXED + 29)	/* the modulus - 1 of the count for NV
							   update of an orderly counter */
#define TPM_PT_MAX_COMMAND_SIZE		(PT_FIXED + 30)	/* the maximum value for commandSize in a command */
#define TPM_PT_MAX_RESPONSE_SIZE	(PT_FIXED + 31)	/* the maximum value for responseSize in a response */
#define TPM_PT_MAX_DIGEST		(PT_FIXED + 32)	/* the maximum size of a digest that can be
							   produced by the TPM */
#define TPM_PT_MAX_OBJECT_CONTEXT	(PT_FIXED + 33)	/* the maximum size of an object context
							   that will be returned by
							   TPM2_ContextSave */
#define TPM_PT_MAX_SESSION_CONTEXT	(PT_FIXED + 34)	/* the maximum size of a session context
							   that will be returned by
							   TPM2_ContextSave */
#define TPM_PT_PS_FAMILY_INDICATOR	(PT_FIXED + 35)	/* platform-specific family (a TPM_PS
							   value)(see Table 26) */
#define TPM_PT_PS_LEVEL			(PT_FIXED + 36)	/* the level of the platform-specific specification */
#define TPM_PT_PS_REVISION		(PT_FIXED + 37)	/* the specification Revision times 100 for
							   the platform-specific specification */
#define TPM_PT_PS_DAY_OF_YEAR		(PT_FIXED + 38)	/* the platform-specific specification day
							   of year using TCG calendar */
#define TPM_PT_PS_YEAR			(PT_FIXED + 39)	/* the platform-specific specification year
							   using the CE */
#define TPM_PT_SPLIT_MAX		(PT_FIXED + 40)	/* the number of split signing operations
							   supported by the TPM */
#define TPM_PT_TOTAL_COMMANDS		(PT_FIXED + 41)	/* total number of commands implemented in the TPM */
#define TPM_PT_LIBRARY_COMMANDS		(PT_FIXED + 42)	/* number of commands from the TPM library
							   that are implemented */
#define TPM_PT_VENDOR_COMMANDS		(PT_FIXED + 43)	/* number of vendor commands that are implemented */
#define TPM_PT_NV_BUFFER_MAX		(PT_FIXED + 44)	/* the maximum data size in one NV write command */
#define PT_VAR				(PT_GROUP * 2)	/* the group of variable properties returned
							   as TPMS_TAGGED_PROPERTY */

/* The properties in this group change because of a Protected Capability other than a firmware
   update. The values are not necessarily persistent across all power transitions. */

#define TPM_PT_PERMANENT		(PT_VAR + 0)	/* TPMA_PERMANENT */
#define TPM_PT_STARTUP_CLEAR		(PT_VAR + 1)	/* TPMA_STARTUP_CLEAR */
#define TPM_PT_HR_NV_INDEX		(PT_VAR + 2)	/* the number of NV Indexes currently defined */
#define TPM_PT_HR_LOADED		(PT_VAR + 3)	/* the number of authorization sessions
							   currently loaded into TPM RAM */
#define TPM_PT_HR_LOADED_AVAIL		(PT_VAR + 4)	/* the number of additional authorization
							   sessions, of any type, that could be
							   loaded into TPM RAM */
#define TPM_PT_HR_ACTIVE		(PT_VAR + 5)	/* the number of active authorization
							   sessions currently being tracked by the
							   TPM */
#define TPM_PT_HR_ACTIVE_AVAIL		(PT_VAR + 6)	/* the number of additional authorization
							   sessions, of any type, that could be
							   created */
#define TPM_PT_HR_TRANSIENT_AVAIL	(PT_VAR + 7)	/* estimate of the number of additional
							   transient objects that could be loaded
							   into TPM RAM */
#define TPM_PT_HR_PERSISTENT		(PT_VAR + 8)	/* the number of persistent objects
							   currently loaded into TPM NV memory */
#define TPM_PT_HR_PERSISTENT_AVAIL	(PT_VAR + 9)	/* the number of additional persistent
							   objects that could be loaded into NV
							   memory */
#define TPM_PT_NV_COUNTERS		(PT_VAR + 10)	/* the number of defined NV Indexes that
							   have the NV TPM_NV_COUNTER attribute SET */
#define TPM_PT_NV_COUNTERS_AVAIL	(PT_VAR + 11)	/* the number of additional NV Indexes that
							   can be defined with their TPM_NT of TPM_NV_COUNTER
							   and the TPM_NV_ORDERLY attribute SET */
#define TPM_PT_ALGORITHM_SET		(PT_VAR + 12)	/* code that limits the algorithms that may
							   be used with the TPM */
#define TPM_PT_LOADED_CURVES		(PT_VAR + 13)	/* the number of loaded ECC curves	 */
#define TPM_PT_LOCKOUT_COUNTER		(PT_VAR + 14)	/* the current value of the lockout counter (failedTries) */
#define TPM_PT_MAX_AUTH_FAIL		(PT_VAR + 15)	/* the number of authorization failures
							   before DA lockout is invoked */
#define TPM_PT_LOCKOUT_INTERVAL		(PT_VAR + 16)	/* the number of seconds before the value
							   reported by TPM_PT_LOCKOUT_COUNTER is
							   decremented */
#define TPM_PT_LOCKOUT_RECOVERY		(PT_VAR + 17)	/* the number of seconds after a lockoutAuth
							   failure before use of lockoutAuth may be
							   attempted again */
#define TPM_PT_NV_WRITE_RECOVERY	(PT_VAR + 18)	/* number of milliseconds before the TPM
							   will accept another command that will
							   modify NV */
#define TPM_PT_AUDIT_COUNTER_0		(PT_VAR + 19)	/* the high-order 32 bits of the command audit counter	 */
#define TPM_PT_AUDIT_COUNTER_1		(PT_VAR + 20)	/* the low-order 32 bits of the command audit counter */

/* Table 25 - Definition of (UINT32) TPM_PT_PCR Constants <IN/OUT, S> */

typedef UINT32 TPM_PT_PCR;

#define TPM_PT_PCR_FIRST	0x00000000	/* bottom of the range of TPM_PT_PCR properties */
#define TPM_PT_PCR_SAVE		0x00000000	/* a SET bit in the TPMS_PCR_SELECT indicates that
						   the PCR is saved and restored by TPM_SU_STATE */
#define TPM_PT_PCR_EXTEND_L0	0x00000001	/* a SET bit in the TPMS_PCR_SELECT indicates that
						   the PCR may be extended from locality 0 */
#define TPM_PT_PCR_RESET_L0	0x00000002	/* a SET bit in the TPMS_PCR_SELECT indicates that
						   the PCR may be reset by TPM2_PCR_Reset() from
						   locality 0 */
#define TPM_PT_PCR_EXTEND_L1	0x00000003	/* a SET bit in the TPMS_PCR_SELECT indicates that
						   the PCR may be extended from locality 1 */
#define TPM_PT_PCR_RESET_L1	0x00000004	/* a SET bit in the TPMS_PCR_SELECT indicates that
						   the PCR may be reset by TPM2_PCR_Reset() from
						   locality 1 */
#define TPM_PT_PCR_EXTEND_L2	0x00000005	/* a SET bit in the TPMS_PCR_SELECT indicates that
						   the PCR may be extended from locality 2 */
#define TPM_PT_PCR_RESET_L2	0x00000006	/* a SET bit in the TPMS_PCR_SELECT indicates that
						   the PCR may be reset by TPM2_PCR_Reset() from
						   locality 2 */
#define TPM_PT_PCR_EXTEND_L3	0x00000007	/* a SET bit in the TPMS_PCR_SELECT indicates that
						   the PCR may be extended from locality 3 */
#define TPM_PT_PCR_RESET_L3	0x00000008	/* a SET bit in the TPMS_PCR_SELECT indicates that
						   the PCR may be reset by TPM2_PCR_Reset() from
						   locality 3 */
#define TPM_PT_PCR_EXTEND_L4	0x00000009	/* a SET bit in the TPMS_PCR_SELECT indicates that
						   the PCR may be extended from locality 4 */
#define TPM_PT_PCR_RESET_L4	0x0000000A	/* a SET bit in the TPMS_PCR_SELECT indicates that
						   the PCR may be reset by TPM2_PCR_Reset() from
						   locality 4 */
#define TPM_PT_PCR_NO_INCREMENT	0x00000011	/* a SET bit in the TPMS_PCR_SELECT indicates that
						   modifications to this PCR (reset or Extend) will
						   not increment the pcrUpdateCounter */
#define TPM_PT_PCR_RESET_L4	0x0000000A	/* a SET bit in the TPMS_PCR_SELECT indicates that
						   the PCR may be reset by TPM2_PCR_Reset() from
						   locality 4 */
#define TPM_PT_PCR_DRTM_RESET	0x00000012	/* a SET bit in the TPMS_PCR_SELECT indicates that
						   the PCR is reset by a DRTM event */
#define TPM_PT_PCR_POLICY	0x00000013	/* a SET bit in the TPMS_PCR_SELECT indicates that
						   the PCR is controlled by policy */
#define TPM_PT_PCR_AUTH		0x00000014	/* a SET bit in the TPMS_PCR_SELECT indicates that
						   the PCR is controlled by an authorization
						   value */
#define TPM_PT_PCR_LAST		0x00000014	/* top of the range of TPM_PT_PCR properties of the
						   implementation */

/* Table 26 - Definition of (UINT32) TPM_PS Constants <OUT> */

typedef UINT32 TPM_PS;

#define TPM_PS_MAIN		0x00000000	/* not platform specific 	*/
#define TPM_PS_PC		0x00000001	/* PC Client	*/
#define TPM_PS_PDA		0x00000002	/* PDA (includes all mobile devices that are not
						   specifically cell phones) */
#define TPM_PS_CELL_PHONE	0x00000003	/* Cell Phone 	*/
#define TPM_PS_SERVER		0x00000004	/* Server WG	*/
#define TPM_PS_PERIPHERAL	0x00000005	/* Peripheral WG	*/
#define TPM_PS_TSS		0x00000006	/* TSS WG	*/
#define TPM_PS_STORAGE		0x00000007	/* Storage WG	*/
#define TPM_PS_AUTHENTICATION	0x00000008	/* Authentication WG	*/
#define TPM_PS_EMBEDDED		0x00000009	/* Embedded WG	*/
#define TPM_PS_HARDCOPY		0x0000000A	/* Hardcopy WG	*/
#define TPM_PS_INFRASTRUCTURE	0x0000000B	/* Infrastructure WG	*/
#define TPM_PS_VIRTUALIZATION	0x0000000C	/* Virtualization WG	*/
#define TPM_PS_TNC		0x0000000D	/* Trusted Network Connect WG	*/
#define TPM_PS_MULTI_TENANT	0x0000000E	/* Multi-tenant WG	*/
#define TPM_PS_TC		0x0000000F	/* Technical Committee*/

/* Table 27 - Definition of Types for Handles */

typedef UINT32	TPM_HANDLE;	/* Handles may refer to objects (keys or data blobs), authorization
				   sessions (HMAC and policy), NV Indexes, permanent TPM locations,
				   and PCR. */

/* Table 28 - Definition of (UINT8) TPM_HT Constants <S> */

typedef UINT8 TPM_HT;

#define TPM_HT_PCR		0x00	/* PCR - consecutive numbers, starting at 0, that reference the PCR registers */
#define TPM_HT_NV_INDEX		0x01	/* NV Index - assigned by the caller	 */
#define TPM_HT_HMAC_SESSION	0x02	/* HMAC Authorization Session - assigned by the TPM when the session is created	 */
#define TPM_HT_LOADED_SESSION	0x02	/* Loaded Authorization Session - used only in the context of TPM2_GetCapability */
#define TPM_HT_POLICY_SESSION	0x03	/* Policy Authorization Session - assigned by the TPM when the session is created */
#define TPM_HT_SAVED_SESSION	0x03	/* Saved Authorization Session - used only in the context of TPM2_GetCapability */
#define TPM_HT_PERMANENT	0x40	/* Permanent Values - assigned by this specification in Table 27	 */
#define TPM_HT_TRANSIENT	0x80	/* Transient Objects - assigned by the TPM when an object is
					   loaded into transient-object memory or when a persistent
					   object is converted to a transient object */
#define TPM_HT_PERSISTENT	0x81	/* Persistent Objects - assigned by the TPM when a loaded
					   transient object is made persistent */

/* Table 29 - Definition of (TPM_HANDLE) TPM_RH Constants <S> */

typedef TPM_HANDLE TPM_RH;

#define TPM_RH_FIRST		0x40000000	/* R		 */
#define TPM_RH_SRK		0x40000000	/* R	not used1	 */
#define TPM_RH_OWNER		0x40000001	/* K, A, P handle references the Storage Primary
						   Seed (SPS), the ownerAuth, and the ownerPolicy */
#define TPM_RH_REVOKE		0x40000002	/* R	not used1	 */
#define TPM_RH_TRANSPORT	0x40000003	/* R	not used1	 */
#define TPM_RH_OPERATOR		0x40000004	/* R	not used1	 */
#define TPM_RH_ADMIN		0x40000005	/* R	not used1	 */
#define TPM_RH_EK		0x40000006	/* R	not used1	 */
#define TPM_RH_NULL		0x40000007	/* K, A, P a handle associated with the null
						   hierarchy, an EmptyAuth authValue, and an Empty
						   Policy authPolicy.  */
#define TPM_RH_UNASSIGNED	0x40000008	/* R value reserved to the TPM to indicate a handle
						   location that has not been initialized or
						   assigned */
#define TPM_RS_PW		0x40000009	/* S authorization value used to indicate a password
						   authorization session */
#define TPM_RH_LOCKOUT		0x4000000A	/* A references the authorization associated with
						   the dictionary attack lockout reset */
#define TPM_RH_ENDORSEMENT	0x4000000B	/* K, A, P references the Endorsement Primary Seed
						   (EPS), endorsementAuth, and endorsementPolicy */
#define TPM_RH_PLATFORM		0x4000000C	/* K, A, P references the Platform Primary Seed
						   (PPS), platformAuth, and platformPolicy */
#define TPM_RH_PLATFORM_NV	0x4000000D	/* C	for phEnableNV */
#define TPM_RH_AUTH_00		0x40000010	/* A Start of a range of authorization values that
						   are vendor-specific.  A TPM may support any of
						   the values in this range as are needed for
						   vendor-specific purposes. Disabled if ehEnable is CLEAR. */
#define TPM_RH_AUTH_FF		0x4000010F	/* A End of the range of vendor-specific
						   authorization values. */
#define TPM_RH_LAST		0x4000010F	/* R	the top of the reserved handle area */

/* Table 30 - Definition of (TPM_HANDLE) TPM_HC Constants <S> */

#define HR_HANDLE_MASK		0x00FFFFFF				/* to mask off the HR	 */
#define HR_RANGE_MASK		0xFF000000				/* to mask off the variable part */
#define HR_SHIFT		24		
#define HR_PCR			(TPM_HT_PCR << HR_SHIFT)		
#define HR_HMAC_SESSION		(TPM_HT_HMAC_SESSION << HR_SHIFT)		
#define HR_POLICY_SESSION	(TPM_HT_POLICY_SESSION << HR_SHIFT)		
#define HR_TRANSIENT		(TPM_HT_TRANSIENT << HR_SHIFT)		
#define HR_PERSISTENT		(TPM_HT_PERSISTENT << HR_SHIFT)		
#define HR_NV_INDEX		(TPM_HT_NV_INDEX << HR_SHIFT)		
#define HR_PERMANENT		(TPM_HT_PERMANENT << HR_SHIFT)		
#define PCR_FIRST		(HR_PCR + 0)					/* first PCR */
#define PCR_LAST		(PCR_FIRST + IMPLEMENTATION_PCR-1)		/* last PCR */
#define HMAC_SESSION_FIRST	(HR_HMAC_SESSION + 0)				/* first HMAC session */
#define HMAC_SESSION_LAST	(HMAC_SESSION_FIRST+MAX_ACTIVE_SESSIONS-1)	/* last HMAC session */
#define LOADED_SESSION_FIRST  	HMAC_SESSION_FIRST				/* used in GetCapability */
#define LOADED_SESSION_LAST	HMAC_SESSION_LAST				/* used in GetCapability */
#define POLICY_SESSION_FIRST	(HR_POLICY_SESSION + 0)				/* first policy session */
#define POLICY_SESSION_LAST	(POLICY_SESSION_FIRST + MAX_ACTIVE_SESSIONS-1)	/* last policy session */
#define TRANSIENT_FIRST		((UINT32)(HR_TRANSIENT + 0))			/* first transient object */
#define ACTIVE_SESSION_FIRST	POLICY_SESSION_FIRST				/* used in GetCapability */
#define ACTIVE_SESSION_LAST	POLICY_SESSION_LAST				/* used in GetCapability */
#define TRANSIENT_LAST		((UINT32)(TRANSIENT_FIRST+MAX_LOADED_OBJECTS-1)) /* last transient object */
#define PERSISTENT_FIRST	((UINT32)(HR_PERSISTENT + 0))			/* first persistent object */
#define PERSISTENT_LAST		((UINT32)(PERSISTENT_FIRST + 0x00FFFFFF))	/* last persistent object */
#define PLATFORM_PERSISTENT	(PERSISTENT_FIRST + 0x00800000)			/* first platform persistent object */
#define NV_INDEX_FIRST		(HR_NV_INDEX + 0)				/* first allowed NV Index */
#define NV_INDEX_LAST		(NV_INDEX_FIRST + 0x00FFFFFF)			/* last allowed NV Index */
#define PERMANENT_FIRST		TPM_RH_FIRST		
#define PERMANENT_LAST		TPM_RH_LAST

/* Table 31 - Definition of (UINT32) TPMA_ALGORITHM Bits */

#if defined TPM_BITFIELD_LE

typedef union {
    struct {
	unsigned int asymmetric : 1;	/* 0 an asymmetric algorithm with public and private portions */
	unsigned int symmetric  : 1;	/* 1 a symmetric block cipher */
	unsigned int hash 	: 1;	/* a hash algorithm */
 	unsigned int object	: 1;	/* an algorithm that may be used as an object type */
	unsigned int Reserved1	: 4; 	/* 7:4 */
	unsigned int signing	: 1;	/* 8 a signing algorithm */
	unsigned int encrypting	: 1;	/* 9 an encryption/decryption algorithm */
	unsigned int method	: 1;	/* 10 a method such as a key derivative function (KDF) */
	unsigned int Reserved2	: 21;	/* 31:11 */
    };
    UINT32 val;
} TPMA_ALGORITHM;

#elif defined TPM_BITFIELD_BE

typedef union {
    struct {
	unsigned int Reserved2	: 21;	/* 31:11 */
	unsigned int method	: 1;	/* 10 a method such as a key derivative function (KDF) */
	unsigned int encrypting	: 1;	/* 9 an encryption/decryption algorithm */
	unsigned int signing	: 1;	/* 8 a signing algorithm */
	unsigned int Reserved1	: 4; 	/* 7:4 */
	unsigned int object	: 1;	/* an algorithm that may be used as an object type */
	unsigned int hash 	: 1;	/* a hash algorithm */
	unsigned int symmetric  : 1;	/* 1 a symmetric block cipher */
	unsigned int asymmetric : 1;	/* 0 an asymmetric algorithm with public and private portions */
    };
    UINT32 val;
} TPMA_ALGORITHM;

#else 

typedef uint32_t TPMA_ALGORITHM;

#endif

#define TPMA_ALGORITHM_ASYMMETRIC 	0x00000001
#define TPMA_ALGORITHM_SYMMETRIC 	0x00000002
#define TPMA_ALGORITHM_HASH		0x00000004
#define TPMA_ALGORITHM_OBJECT		0x00000008
#define TPMA_ALGORITHM_RESERVED1	0x000000f0
#define TPMA_ALGORITHM_SIGNING		0x00000100
#define TPMA_ALGORITHM_ENCRYPTING	0x00000200
#define TPMA_ALGORITHM_METHOD		0x00000400
#define TPMA_ALGORITHM_RESERVED2	0xfffff800

#define TPMA_ALGORITHM_RESERVED ( 	\
    TPMA_ALGORITHM_RESERVED1 |		\
    TPMA_ALGORITHM_RESERVED2 )

/* Table 32 - Definition of (UINT32) TPMA_OBJECT Bits */

#if defined TPM_BITFIELD_LE

typedef union {
    struct {
	unsigned int Reserved1 		: 1;	/* 0 shall be zero */
	unsigned int fixedTPM 		: 1;	/* 1 The hierarchy of the object, as indicated by its Qualified Name, may not change. */
	unsigned int stClear 		: 1;	/* 2 Previously saved contexts of this object may not be loaded after Startup(CLEAR). */
	unsigned int Reserved2 		: 1;	/* 3 shall be zero */
	unsigned int fixedParent 	: 1;	/* 4 The parent of the object may not change. */
	unsigned int sensitiveDataOrigin : 1;	/* 5 the TPM generated all of the sensitive data other than the authValue. */
	unsigned int userWithAuth 	: 1;	/* 6 HMAC session or with a password */ 
	unsigned int adminWithPolicy 	: 1;	/* 7 policy session. */
	unsigned int Reserved3 		: 2;	/* 9:8	shall be zero */
	unsigned int noDA 		: 1;	/* 10	The object is not subject to dictionary attack protections. */
	unsigned int encryptedDuplication : 1;	/* 11 */
	unsigned int Reserved4 		: 4;	/* 15:12	shall be zero */
	unsigned int restricted 	: 1;	/* 16	Key usage is restricted to manipulate structures of known format */
	unsigned int decrypt 		: 1;	/* 17	The private portion of the key may be used to decrypt. */
	unsigned int sign 		: 1;	/* 18 For a symmetric cipher object, the private
						   portion of the key may be used to encrypt.  For
						   other objects, the private portion of the key may
						   be used to sign. */
	unsigned int Reserved5		: 13;	/* 31:19 	shall be zero */
    };
    UINT32 val;
} TPMA_OBJECT;

#elif defined TPM_BITFIELD_BE

typedef union {
    struct {
	unsigned int Reserved5		: 13;	/* 31:19 	shall be zero */
	unsigned int sign 		: 1;	/* 18 For a symmetric cipher object, the private
						   portion of the key may be used to encrypt.  For
						   other objects, the private portion of the key may
						   be used to sign. */
	unsigned int decrypt 		: 1;	/* 17	The private portion of the key may be used to decrypt. */
	unsigned int restricted 	: 1;	/* 16	Key usage is restricted to manipulate structures of known format */
	unsigned int Reserved4 		: 4;	/* 15:12	shall be zero */
	unsigned int encryptedDuplication : 1;	/* 11 */
	unsigned int noDA 		: 1;	/* 10	The object is not subject to dictionary attack protections. */
	unsigned int Reserved3 		: 2;	/* 9:8	shall be zero */
	unsigned int adminWithPolicy 	: 1;	/* 7 policy session. */
	unsigned int userWithAuth 	: 1;	/* 6 HMAC session or with a password */ 
	unsigned int sensitiveDataOrigin : 1;	/* 5 the TPM generated all of the sensitive data other than the authValue. */
	unsigned int fixedParent 	: 1;	/* 4 The parent of the object may not change. */
	unsigned int Reserved2 		: 1;	/* 3 shall be zero */
	unsigned int stClear 		: 1;	/* 2 Previously saved contexts of this object may not be loaded after Startup(CLEAR). */
	unsigned int fixedTPM 		: 1;	/* 1 The hierarchy of the object, as indicated by its Qualified Name, may not change. */
	unsigned int Reserved1 		: 1;	/* 0 shall be zero */
    };
    UINT32 val;
} TPMA_OBJECT;

#else 

typedef uint32_t TPMA_OBJECT;
	
#endif

#define TPMA_OBJECT_RESERVED1			0x00000001
#define TPMA_OBJECT_FIXEDTPM			0x00000002
#define TPMA_OBJECT_STCLEAR			0x00000004
#define TPMA_OBJECT_RESERVED2			0x00000008
#define TPMA_OBJECT_FIXEDPARENT			0x00000010
#define TPMA_OBJECT_SENSITIVEDATAORIGIN		0x00000020
#define TPMA_OBJECT_USERWITHAUTH		0x00000040
#define TPMA_OBJECT_ADMINWITHPOLICY		0x00000080
#define TPMA_OBJECT_RESERVED3			0x00000300
#define TPMA_OBJECT_NODA			0x00000400
#define TPMA_OBJECT_ENCRYPTEDDUPLICATION	0x00000800
#define TPMA_OBJECT_RESERVED4			0x0000f000
#define TPMA_OBJECT_RESTRICTED			0x00010000
#define TPMA_OBJECT_DECRYPT			0x00020000
#define TPMA_OBJECT_SIGN			0x00040000
#define TPMA_OBJECT_RESERVED5			0xfff80000

#define TPMA_OBJECT_RESERVED ( \
    TPMA_OBJECT_RESERVED1 |    \
    TPMA_OBJECT_RESERVED2 |    \
    TPMA_OBJECT_RESERVED3 |    \
    TPMA_OBJECT_RESERVED4 |    \
    TPMA_OBJECT_RESERVED5 )			

/* Table 33 - Definition of (UINT8) TPMA_SESSION Bits <IN/OUT> */

#if defined TPM_BITFIELD_LE

typedef union {
    struct {
	unsigned int continueSession 	: 1;		/* 0	the session is to remain active after successful completion of the command */
	unsigned int auditExclusive 	: 1;		/* 1	executed if the session is exclusive at the start of the command */
	unsigned int auditReset 	: 1;		/* 2	audit digest of the session should be initialized  */
	unsigned int Reserved 		: 2;		/* 4:3	shall be CLEAR */
	unsigned int decrypt 		: 1;		/* 5	first parameter in the command is symmetrically encrypted */
	unsigned int encrypt 		: 1;		/* 6	TPM should use this session to encrypt the first parameter in the response */
	unsigned int audit 		: 1;		/* 7	session is for audit */
    };
    UINT8 val;
} TPMA_SESSION;

#elif defined TPM_BITFIELD_BE

typedef union {
    struct {
	unsigned int audit 		: 1;		/* 7	session is for audit */
	unsigned int encrypt 		: 1;		/* 6	TPM should use this session to encrypt the first parameter in the response */
	unsigned int decrypt 		: 1;		/* 5	first parameter in the command is symmetrically encrypted */
	unsigned int Reserved 		: 2;		/* 4:3	shall be CLEAR */
	unsigned int auditReset 	: 1;		/* 2	audit digest of the session should be initialized  */
	unsigned int auditExclusive 	: 1;		/* 1	executed if the session is exclusive at the start of the command */
	unsigned int continueSession 	: 1;		/* 0	the session is to remain active after successful completion of the command */
    };
    UINT8 val;
} TPMA_SESSION;

#else 

typedef uint8_t TPMA_SESSION;

#endif

#define TPMA_SESSION_CONTINUESESSION	0x01
#define TPMA_SESSION_AUDITEXCLUSIVE	0x02
#define TPMA_SESSION_AUDITRESET		0x04
#define TPMA_SESSION_DECRYPT		0x20
#define TPMA_SESSION_ENCRYPT		0x40
#define TPMA_SESSION_AUDIT		0x80

#define TPMA_SESSION_RESERVED		0x18

/* Table 34 - Definition of (UINT8) TPMA_LOCALITY Bits <IN/OUT> */

#if defined TPM_BITFIELD_LE

typedef union {
    struct {
	unsigned int TPM_LOC_ZERO	: 1;	/* 0 */
	unsigned int TPM_LOC_ONE	: 1;	/* 1 */
	unsigned int TPM_LOC_TWO	: 1;	/* 2 */
	unsigned int TPM_LOC_THREE	: 1;	/* 3 */
	unsigned int TPM_LOC_FOUR	: 1;	/* 4 */
	unsigned int Extended		: 3;	/* 7:5 */
    };
    UINT8 val;
} TPMA_LOCALITY;

#elif defined TPM_BITFIELD_BE

typedef union {
    struct {
	unsigned int Extended		: 3;	/* 7:5 */
	unsigned int TPM_LOC_FOUR	: 1;	/* 4 */
	unsigned int TPM_LOC_THREE	: 1;	/* 3 */
	unsigned int TPM_LOC_TWO	: 1;	/* 2 */
	unsigned int TPM_LOC_ONE	: 1;	/* 1 */
	unsigned int TPM_LOC_ZERO	: 1;	/* 0 */
    };
    UINT8 val;
} TPMA_LOCALITY;

#else 

typedef uint8_t TPMA_LOCALITY;

#define TPMA_LOCALITY_ZERO		0x01
#define TPMA_LOCALITY_ONE		0x02
#define TPMA_LOCALITY_TWO		0x04
#define TPMA_LOCALITY_THREE		0x08
#define TPMA_LOCALITY_FOUR		0x10
#define TPMA_LOCALITY_EXTENDED		0xe0

#endif

/* Table 35 - Definition of (UINT32) TPMA_PERMANENT Bits <OUT> */

#if defined TPM_BITFIELD_LE

typedef union {
    struct {
	unsigned int ownerAuthSet	: 1;	/* 0	TPM2_HierarchyChangeAuth() with ownerAuth has been executed since the last TPM2_Clear(). */
	unsigned int endorsementAuthSet	: 1;	/* 1	TPM2_HierarchyChangeAuth() with endorsementAuth has been executed since the last TPM2_Clear(). */
	unsigned int lockoutAuthSet	: 1;	/* 2	TPM2_HierarchyChangeAuth() with lockoutAuth has been executed since the last TPM2_Clear(). */
	unsigned int Reserved1		: 5;	/* 7:3	 */
	unsigned int disableClear	: 1;	/* 8	TPM2_Clear() is disabled. */
	unsigned int inLockout		: 1;	/* 9	The TPM is in lockout and commands that require authorization
						   with other than Platform Authorization or Lockout Authorization will not succeed. */
	unsigned int tpmGeneratedEPS	: 1;	/* 10	The EPS was created by the TPM. */
	unsigned int Reserved2		: 21;	/* 31:11 */
    };
    UINT32 val;
} TPMA_PERMANENT;

#elif defined TPM_BITFIELD_BE

typedef union {
    struct {
	unsigned int Reserved2		: 21;	/* 31:11 */
	unsigned int tpmGeneratedEPS	: 1;	/* 10	The EPS was created by the TPM. */
	unsigned int inLockout		: 1;	/* 9	The TPM is in lockout and commands that require authorization with other than Platform Authorization will not succeed. */
	unsigned int disableClear	: 1;	/* 8	TPM2_Clear() is disabled. */
	unsigned int Reserved1		: 5;	/* 7:3	 */
	unsigned int lockoutAuthSet	: 1;	/* 2	TPM2_HierarchyChangeAuth() with lockoutAuth has been executed since the last TPM2_Clear(). */
	unsigned int endorsementAuthSet	: 1;	/* 1	TPM2_HierarchyChangeAuth() with endorsementAuth has been executed since the last TPM2_Clear(). */
	unsigned int ownerAuthSet	: 1;	/* 0	TPM2_HierarchyChangeAuth() with ownerAuth has been executed since the last TPM2_Clear(). */
    };
    UINT32 val;
} TPMA_PERMANENT;

#else

typedef uint32_t TPMA_PERMANENT;

#define TPMA_PERMANENT_OWNERAUTHSET		0x00000001
#define TPMA_PERMANENT_ENDORSEMENTAUTHSET	0x00000002
#define TPMA_PERMANENT_LOCKOUTAUTHSET		0x00000004
#define TPMA_PERMANENT_RESERVED1		0x000000f8
#define TPMA_PERMANENT_DISABLECLEAR		0x00000100
#define TPMA_PERMANENT_INLOCKOUT		0x00000200
#define TPMA_PERMANENT_TPMGENERATEDEPS		0x00000400
#define TPMA_PERMANENT_RESERVED2		0xfffff800

#endif

/* Table 36 - Definition of (UINT32) TPMA_STARTUP_CLEAR Bits <OUT> */

#if defined TPM_BITFIELD_LE

typedef union {
    struct {
	unsigned int phEnable		: 1;	/* 0 The platform hierarchy is enabled and platformAuth or platformPolicy may be used for authorization. */
	unsigned int shEnable		: 1;	/* 1 The Storage hierarchy is enabled and ownerAuth or ownerPolicy may be used for authorization. */
	unsigned int ehEnable		: 1;	/* 2 The EPS hierarchy is enabled and endorsementAuth may be used to authorize commands. */
	unsigned int phEnableNV		: 1;	/* 3 NV indices that have TPMA_PLATFORM_CREATE SET may be read or written.  */
	unsigned int Reserved		: 27;	/* 30:4 shall be zero */
	unsigned int orderly		: 1;	/* 31 The TPM received a TPM2_Shutdown() and a matching TPM2_Startup(). */
    };
    UINT32 val;
} TPMA_STARTUP_CLEAR;

#elif defined TPM_BITFIELD_BE

typedef union {
    struct {
	unsigned int orderly		: 1;	/* 31 The TPM received a TPM2_Shutdown() and a matching TPM2_Startup(). */
	unsigned int Reserved		: 27;	/* 30:4 shall be zero */
	unsigned int phEnableNV		: 1;	/* 3 NV indices that have TPMA_PLATFORM_CREATE SET may be read or written.  */
	unsigned int ehEnable		: 1;	/* 2 The EPS hierarchy is enabled and endorsementAuth may be used to authorize commands. */
	unsigned int shEnable		: 1;	/* 1 The Storage hierarchy is enabled and ownerAuth or ownerPolicy may be used for authorization. */
	unsigned int phEnable		: 1;	/* 0 The platform hierarchy is enabled and platformAuth or platformPolicy may be used for authorization. */
    };
    UINT32 val;
} TPMA_STARTUP_CLEAR;

#else 

typedef uint32_t TPMA_STARTUP_CLEAR;

#define TPMA_STARTUP_CLEAR_PHENABLE		0x00000001
#define TPMA_STARTUP_CLEAR_SHENABLE		0x00000002
#define TPMA_STARTUP_CLEAR_EHENABLE		0x00000004
#define TPMA_STARTUP_CLEAR_PHENABLENV		0x00000008
#define TPMA_STARTUP_CLEAR_RESERVED		0x7ffffff0
#define TPMA_STARTUP_CLEAR_ORDERLY		0x80000000

#endif

/* Table 37 - Definition of (UINT32) TPMA_MEMORY Bits <Out> */

#if defined TPM_BITFIELD_LE

typedef union {
    struct {
	unsigned int sharedRAM		: 1;	/* 0	RAM memory used for authorization session contexts is shared with the memory used for transient objects */
	unsigned int sharedNV		: 1;	/* 1	indicates that the NV memory used for persistent objects is shared with the NV memory used for NV Index values */
	unsigned int objectCopiedToRam	: 1;	/* 2	indicates that the TPM copies persistent objects to a transient-object slot in RAM */
	unsigned int Reserved		: 29;	/* 31:3	shall be zero */
    };
    UINT32 val;
} TPMA_MEMORY;

#elif defined TPM_BITFIELD_BE

typedef union {
    struct {
	unsigned int Reserved		: 29;	/* 31:3	shall be zero */
	unsigned int objectCopiedToRam	: 1;	/* 2	indicates that the TPM copies persistent objects to a transient-object slot in RAM */
	unsigned int sharedNV		: 1;	/* 1	indicates that the NV memory used for persistent objects is shared with the NV memory used for NV Index values */
	unsigned int sharedRAM		: 1;	/* 0	RAM memory used for authorization session contexts is shared with the memory used for transient objects */
    };
    UINT32 val;
} TPMA_MEMORY;

#else 

typedef uint32_t TPMA_MEMORY;

#define TPMA_MEMORY_SHAREDRAM		0x00000001
#define TPMA_MEMORY_SHAREDNV		0x00000002
#define TPMA_MEMORY_OBJECTCOPIEDTORAM	0x00000004
#define TPMA_MEMORY_RESERVED		0xfffffff8

#endif

/* Table 38 - Definition of (TPM_CC) TPMA_CC Bits <OUT> */

#if defined TPM_BITFIELD_LE

typedef union {
    struct {
	unsigned int commandIndex : 16;	/* 15:0	indicates the command being selected */
	unsigned int Reserved	: 6;	/* 21:16 shall be zero */
	unsigned int nv		: 1;	/* 22 indicates that the command may write to NV */
	unsigned int extensive	: 1;	/* 23 This command could flush any number of loaded contexts. */
	unsigned int flushed	: 1;	/* 24 The context associated with any transient handle in the command will be flushed when this command completes. */
	unsigned int cHandles	: 3;	/* 27:25 indicates the number of the handles in the handle area for this command */
	unsigned int rHandle	: 1;	/* 28 indicates the presence of the handle area in the input */
	unsigned int V		: 1;	/* 29 indicates that the command is vendor-specific */
	unsigned int Res	: 2;	/* 31:30	allocated for software; shall be zero */
    };
    UINT32 val;
} TPMA_CC;

#elif defined TPM_BITFIELD_BE

typedef union {
    struct {
	unsigned int Res		: 2;	/* 31:30	allocated for software; shall be zero */
	unsigned int V		: 1;	/* 29 indicates that the command is vendor-specific */
	unsigned int rHandle	: 1;	/* 28 indicates the presence of the handle area in the input */
	unsigned int cHandles	: 3;	/* 27:25 indicates the number of the handles in the handle area for this command */
	unsigned int flushed	: 1;	/* 24 The context associated with any transient handle in the command will be flushed when this command completes. */
	unsigned int extensive	: 1;	/* 23 This command could flush any number of loaded contexts. */
	unsigned int nv		: 1;	/* 22 indicates that the command may write to NV */
	unsigned int Reserved	: 6;	/* 21:16 shall be zero */
	unsigned int commandIndex : 16;	/* 15:0	indicates the command being selected */
    };
    UINT32 val;
} TPMA_CC;

#else

typedef uint32_t TPMA_CC;

#define TPMA_CC_COMMANDINDEX	0x0000ffff
#define TPMA_CC_RESERVED1	0x003f0000
#define TPMA_CC_NV		0x00400000
#define TPMA_CC_EXTENSIVE	0x00800000
#define TPMA_CC_FLUSHED		0x01000000
#define TPMA_CC_CHANDLES	0x0e000000
#define TPMA_CC_RHANDLE		0x10000000
#define TPMA_CC_V		0x20000000
#define TPMA_CC_RES		0xc0000000

#endif

#define TPMA_CC_RESERVED	(0x003f0000 | 0xc0000000)

/* Table 39 - Definition of (BYTE) TPMI_YES_NO Type */

typedef BYTE TPMI_YES_NO;

#define NO	0
#define YES	1	

/* Table 40 - Definition of (TPM_HANDLE) TPMI_DH_OBJECT Type */

typedef TPM_HANDLE TPMI_DH_OBJECT;

/* Table 41 - Definition of (TPM_HANDLE) TPMI_DH_PERSISTENT Type */

typedef TPM_HANDLE TPMI_DH_PERSISTENT;

/* Table 42 - Definition of (TPM_HANDLE) TPMI_DH_ENTITY Type <IN> */

typedef TPM_HANDLE TPMI_DH_ENTITY;

/* Table 43 - Definition of (TPM_HANDLE) TPMI_DH_PCR Type <IN> */

typedef TPM_HANDLE TPMI_DH_PCR;

/* Table 44 - Definition of (TPM_HANDLE) TPMI_SH_AUTH_SESSION Type <IN/OUT> */

typedef TPM_HANDLE TPMI_SH_AUTH_SESSION;

/* Table 45 - Definition of (TPM_HANDLE) TPMI_SH_HMAC Type <IN/OUT> */

typedef TPM_HANDLE TPMI_SH_HMAC;

/* Table 46 - Definition of (TPM_HANDLE) TPMI_SH_POLICY Type <IN/OUT> */

typedef TPM_HANDLE TPMI_SH_POLICY;

/* Table 47 - Definition of (TPM_HANDLE) TPMI_DH_CONTEXT Type  */

typedef TPM_HANDLE TPMI_DH_CONTEXT;

/* Table 48 - Definition of (TPM_HANDLE) TPMI_RH_HIERARCHY Type  */

typedef TPM_HANDLE TPMI_RH_HIERARCHY;

/* Table 49 - Definition of (TPM_HANDLE) TPMI_RH_ENABLES Type */

typedef TPM_HANDLE TPMI_RH_ENABLES;

/* Table 50 - Definition of (TPM_HANDLE) TPMI_RH_HIERARCHY_AUTH Type <IN> */

typedef TPM_HANDLE TPMI_RH_HIERARCHY_AUTH;

/* Table 51 - Definition of (TPM_HANDLE) TPMI_RH_PLATFORM Type <IN> */

typedef TPM_HANDLE TPMI_RH_PLATFORM;

/* Table 52 - Definition of (TPM_HANDLE) TPMI_RH_OWNER Type <IN> */

typedef TPM_HANDLE TPMI_RH_OWNER;

/* Table 53 - Definition of (TPM_HANDLE) TPMI_RH_ENDORSEMENT Type <IN> */

typedef TPM_HANDLE TPMI_RH_ENDORSEMENT;

/* Table 54 - Definition of (TPM_HANDLE) TPMI_RH_PROVISION Type <IN> */

typedef TPM_HANDLE TPMI_RH_PROVISION;

/* Table 55 - Definition of (TPM_HANDLE) TPMI_RH_CLEAR Type <IN> */

typedef TPM_HANDLE TPMI_RH_CLEAR;

/* Table 56 - Definition of (TPM_HANDLE) TPMI_RH_NV_AUTH Type <IN> */

typedef TPM_HANDLE TPMI_RH_NV_AUTH;

/* Table 57 - Definition of (TPM_HANDLE) TPMI_RH_LOCKOUT Type <IN> */

typedef TPM_HANDLE TPMI_RH_LOCKOUT;

/* Table 58 - Definition of (TPM_HANDLE) TPMI_RH_NV_INDEX Type <IN/OUT> */

typedef TPM_HANDLE TPMI_RH_NV_INDEX;

/* Table 59 - Definition of (TPM_ALG_ID) TPMI_ALG_HASH Type  */

typedef TPM_ALG_ID TPMI_ALG_HASH;

/* Table 60 - Definition of (TPM_ALG_ID) TPMI_ALG_ASYM Type */

typedef TPM_ALG_ID TPMI_ALG_ASYM;

/* Table 61 - Definition of (TPM_ALG_ID) TPMI_ALG_SYM Type */

typedef TPM_ALG_ID TPMI_ALG_SYM;

/* Table 62 - Definition of (TPM_ALG_ID) TPMI_ALG_SYM_OBJECT Type */

typedef TPM_ALG_ID TPMI_ALG_SYM_OBJECT;

/* Table 63 - Definition of (TPM_ALG_ID) TPMI_ALG_SYM_MODE Type */

typedef TPM_ALG_ID TPMI_ALG_SYM_MODE;

/* Table 64 - Definition of (TPM_ALG_ID) TPMI_ALG_KDF Type */

typedef TPM_ALG_ID TPMI_ALG_KDF;

/* Table 65 - Definition of (TPM_ALG_ID) TPMI_ALG_SIG_SCHEME Type */

typedef TPM_ALG_ID TPMI_ALG_SIG_SCHEME;

/* Table 66 - Definition of (TPM_ALG_ID) TPMI_ECC_KEY_EXCHANGE Type */

typedef TPM_ALG_ID TPMI_ECC_KEY_EXCHANGE;

/* Table 67 - Definition of (TPM_ST) TPMI_ST_COMMAND_TAG Type */

typedef TPM_ST TPMI_ST_COMMAND_TAG;

/* Table 68 - Definition of TPMS_EMPTY Structure <IN/OUT> */

typedef struct {
    /* a structure with no member */
    BYTE empty[0];
} TPMS_EMPTY;

/* Table 69 - Definition of TPMS_ALGORITHM_DESCRIPTION Structure <OUT> */
typedef struct {
    TPM_ALG_ID		alg;		/* an algorithm	*/
    TPMA_ALGORITHM 	attributes;	/* the attributes of the algorithm */
} TPMS_ALGORITHM_DESCRIPTION;

/* Table 70 - Definition of TPMU_HA Union <IN/OUT, S> */

typedef union {
#ifdef TPM_ALG_SHA1
    BYTE	sha1 [SHA1_DIGEST_SIZE];	/* TPM_ALG_SHA1 */
#endif
#ifdef TPM_ALG_SHA256	
    BYTE	sha256 [SHA256_DIGEST_SIZE]; 	/* TPM_ALG_SHA256 */
#endif
#ifdef TPM_ALG_SHA384
    BYTE	sha384 [SHA384_DIGEST_SIZE];	/* TPM_ALG_SHA384 */
#endif
#ifdef TPM_ALG_SHA512
    BYTE	sha512 [SHA512_DIGEST_SIZE];	/* TPM_ALG_SHA512 */
#endif
#ifdef TPM_ALG_SM3_256
    BYTE	sm3_256 [SM3_256_DIGEST_SIZE];	/* TPM_ALG_SM3_256 */
#endif
} TPMU_HA;

/* Table 71 - Definition of TPMT_HA Structure <IN/OUT> */

typedef struct {
    TPMI_ALG_HASH	hashAlg;	/* selector of the hash contained in the digest that implies the size of the digest */
    TPMU_HA		digest;		/* the digest data */
} TPMT_HA;

/* Table 72 - Definition of TPM2B_DIGEST Structure */

typedef struct {
    UINT16    size;
    BYTE      buffer[sizeof(TPMU_HA)];
} DIGEST_2B;

typedef union {
    DIGEST_2B    t;
    TPM2B        b;
} TPM2B_DIGEST;

/* Table 73 - Definition of TPM2B_DATA Structure */

typedef struct {
    UINT16	size;				/* size in octets of the buffer field; may be 0 */
    BYTE	buffer[sizeof(TPMT_HA)]; 	/* the buffer area that contains the algorithm ID and the digest */
} DATA_2B;

typedef union {
    DATA_2B t;
    TPM2B   b;
} TPM2B_DATA;

/* Table 74 - Definition of Types for TPM2B_NONCE */

typedef TPM2B_DIGEST	TPM2B_NONCE;	/* size limited to the same as the digest structure */

/* Table 75 - Definition of Types for TPM2B_AUTH */

typedef TPM2B_DIGEST	TPM2B_AUTH;	/* size limited to the same as the digest structure */

/* This is not in Part 2, but the concatenation of two digests to create an HMAC key is used often
   enough that it's worth putting in a central location.

   In Part 1 19.6.8 sessionKey Creation - authValue || salt.
   In Part 1 19.6.5 HMAC Computation - sessionKey || authValue

   I think both could be TPMU_HA, but the TPM reference code seems to use TPMT_HA.
*/

typedef struct {
    UINT16    size;
    BYTE      buffer[sizeof(TPMU_HA) +	/* TPM2B_AUTH authValue */
		     sizeof(TPMT_HA)];	/* salt */
} KEY_2B;

typedef union {
    KEY_2B    t;
    TPM2B     b;
} TPM2B_KEY;

/* Table 76 - Definition of Types for TPM2B_OPERAND */

typedef TPM2B_DIGEST	TPM2B_OPERAND;	/* size limited to the same as the digest structure */

/* Table 77 - Definition of TPM2B_EVENT Structure */

typedef struct {
    UINT16	size;			/* size of the operand */
    BYTE	buffer [1024];		/* the operand */
} EVENT_2B;

typedef union {
    EVENT_2B t;
    TPM2B    b;
} TPM2B_EVENT;

/* Table 78 - Definition of TPM2B_MAX_BUFFER Structure */

/* MAX_DIGEST_BUFFER is TPM-dependent but is required to be at least 1,024. */

#define MAX_DIGEST_BUFFER 1024

typedef struct {
    UINT16	size;				/* size of the buffer */
    BYTE	buffer [MAX_DIGEST_BUFFER];	/* the operand  */
} MAX_BUFFER_2B;

typedef union {
    MAX_BUFFER_2B t;
    TPM2B         b;
} TPM2B_MAX_BUFFER;

/* Table 79 - Definition of TPM2B_MAX_NV_BUFFER Structure */

typedef struct {
    UINT16	size;				/* size of the buffer */
    BYTE	buffer [MAX_NV_BUFFER_SIZE];	/* the operand  */
} MAX_NV_BUFFER_2B;

typedef union {
    MAX_NV_BUFFER_2B t;
    TPM2B            b;
} TPM2B_MAX_NV_BUFFER;

/* Table 80 - Definition of TPM2B_TIMEOUT Structure <IN/OUT> */

typedef TPM2B_DIGEST	TPM2B_TIMEOUT;	/* size limited to the same as the digest structure */

/* Table 81 - Definition of TPM2B_IV Structure <IN/OUT> */

typedef struct {
    UINT16	size;				/* size of the IV value */
    BYTE	buffer [MAX_SYM_BLOCK_SIZE]; 	/* the IVvalue */
} IV_2B;

typedef union {
    IV_2B t;
    TPM2B b;
} TPM2B_IV;

/* Table 82 - Definition of TPMU_NAME Union <> */

typedef union {
    TPMT_HA	digest;		/* when the Name is a digest */
    TPM_HANDLE	handle;		/* when the Name is a handle */
} TPMU_NAME;

/* Table 83 - Definition of TPM2B_NAME Structure */

typedef struct {
    UINT16	size;				/* size of the Name structure */
    BYTE	name[sizeof(TPMU_NAME)];	/* the Name structure */
} NAME_2B;

typedef union {
    NAME_2B t;
    TPM2B   b;
} TPM2B_NAME;

/* Table 84 - Definition of TPMS_PCR_SELECT Structure */

typedef struct {
    UINT8	sizeofSelect;			/* the size in octets of the pcrSelect array */
    BYTE 	pcrSelect [PCR_SELECT_MAX];	/* the bit map of selected PCR */
} TPMS_PCR_SELECT;

/* Table 85 - Definition of TPMS_PCR_SELECTION Structure */

typedef struct {
    TPMI_ALG_HASH	hash;				/* the hash algorithm associated with the selection */
    UINT8		sizeofSelect;			/* the size in octets of the pcrSelect array */
    BYTE 		pcrSelect [PCR_SELECT_MAX];	/* the bit map of selected PCR */
} TPMS_PCR_SELECTION;

/* Table 88 - Definition of TPMT_TK_CREATION Structure */

typedef struct {
    TPM_ST		tag;		/* ticket structure tag TPM_ST_CREATION */
    TPMI_RH_HIERARCHY	hierarchy;	/* the hierarchy containing name */
    TPM2B_DIGEST	digest;		/* This shall be the HMAC produced using a proof value of hierarchy. */
} TPMT_TK_CREATION;

/* Table 89 - Definition of TPMT_TK_VERIFIED Structure */

typedef struct {
    TPM_ST		tag;		/* ticket structure tag TPM_ST_VERIFIED */
    TPMI_RH_HIERARCHY	hierarchy;	/* the hierarchy containing keyName */
    TPM2B_DIGEST	digest;		/* This shall be the HMAC produced using a proof value of hierarchy. */
} TPMT_TK_VERIFIED;

/* Table 90 - Definition of TPMT_TK_AUTH Structure */

typedef struct {
    TPM_ST		tag;		/* ticket structure tag TPM_ST_AUTH_SIGNED, TPM_ST_AUTH_SECRET */
    TPMI_RH_HIERARCHY	hierarchy;	/* the hierarchy of the object used to produce the ticket */
    TPM2B_DIGEST	digest;		/* This shall be the HMAC produced using a proof value of hierarchy. */
} TPMT_TK_AUTH;

/* Table 91 - Definition of TPMT_TK_HASHCHECK Structure */

typedef struct {
    TPM_ST		tag;		/* ticket structure tag TPM_ST_HASHCHECK */
    TPMI_RH_HIERARCHY	hierarchy;	/* the hierarchy */
    TPM2B_DIGEST	digest;		/* This shall be the HMAC produced using a proof value of hierarchy. */
} TPMT_TK_HASHCHECK;

/* Table 92 - Definition of TPMS_ALG_PROPERTY Structure <OUT> */

typedef struct {
    TPM_ALG_ID		alg;		/* an algorithm identifier */
    TPMA_ALGORITHM	algProperties;	/* the attributes of the algorithm */
} TPMS_ALG_PROPERTY;

/* Table 93 - Definition of TPMS_TAGGED_PROPERTY Structure <OUT> */

typedef struct {
    TPM_PT	property;	/* a property identifier */
    UINT32	value;		/* the value of the property */
} TPMS_TAGGED_PROPERTY;

/* Table 94 - Definition of TPMS_TAGGED_PCR_SELECT Structure <OUT> */

typedef struct {
    TPM_PT_PCR	tag;				/* the property identifier */
    UINT8	sizeofSelect;			/* the size in octets of the pcrSelect array */
    BYTE 	pcrSelect [PCR_SELECT_MAX];	/* the bit map of PCR with the identified property */
} TPMS_TAGGED_PCR_SELECT;

/* Table 95 - Definition of TPML_CC Structure */

typedef struct {
    UINT32	count;				/* number of commands in the commandCode list; may be 0 */
    TPM_CC	commandCodes[MAX_CAP_CC];	/* a list of command codes */
} TPML_CC;

/* Table 96 - Definition of TPML_CCA Structure <OUT> */

typedef struct {
    UINT32	count;				/* number of values in the commandAttributes list; may be 0 */
    TPMA_CC	commandAttributes[MAX_CAP_CC];	/* a list of command codes attributes */
} TPML_CCA;

/* Table 97 - Definition of TPML_ALG Structure */

typedef struct {
    UINT32	count;				/* number of algorithms in the algorithms list; may be 0 */
    TPM_ALG_ID	algorithms[MAX_ALG_LIST_SIZE];	/* a list of algorithm IDs */
} TPML_ALG;

/* Table 98 - Definition of TPML_HANDLE Structure <OUT> */

typedef struct {
    UINT32	count;				/* the number of handles in the list may have a value of 0 */
    TPM_HANDLE 	handle[MAX_CAP_HANDLES];	/* an array of handles */
} TPML_HANDLE;

/* Table 99 - Definition of TPML_DIGEST Structure */

typedef struct {
    UINT32		count;		/* number of digests in the list, minimum is two for TPM2_PolicyOR(). */
    TPM2B_DIGEST	digests[8];	/* a list of digests */
} TPML_DIGEST;

/* Table 100 - Definition of TPML_DIGEST_VALUES Structure */

typedef struct {
    UINT32	count;			/* number of digests in the list */
    TPMT_HA	digests[HASH_COUNT];	/* a list of tagged digests */
} TPML_DIGEST_VALUES;

/* Table 101 - Definition of TPM2B_DIGEST_VALUES Structure */

typedef struct {
    UINT16	size;					/* size of the operand buffer */
    BYTE	buffer [sizeof(TPML_DIGEST_VALUES)];	/* the operand */
} TPM2B_DIGEST_VALUES;

/* Table 102 - Definition of TPML_PCR_SELECTION Structure */

typedef struct {
    UINT32		count;				/* number of selection structures A value of zero is allowed. */
    TPMS_PCR_SELECTION	pcrSelections[HASH_COUNT];	/* list of selections */
} TPML_PCR_SELECTION;

/* Table 103 - Definition of TPML_ALG_PROPERTY Structure <OUT> */

typedef struct {
    UINT32		count;				/* number of algorithm properties structures A value of zero is allowed. */
    TPMS_ALG_PROPERTY	algProperties[MAX_CAP_ALGS];	/* list of properties */
} TPML_ALG_PROPERTY;

/* Table 104 - Definition of TPML_TAGGED_TPM_PROPERTY Structure <OUT> */

typedef struct {
    UINT32			count;					/* number of properties A value of zero is allowed. */
    TPMS_TAGGED_PROPERTY	tpmProperty[MAX_TPM_PROPERTIES];	/* an array of tagged properties */
} TPML_TAGGED_TPM_PROPERTY;

/* Table 105 - Definition of TPML_TAGGED_PCR_PROPERTY Structure <OUT> */

typedef struct {
    UINT32			count;					/* number of properties A value of zero is allowed. */
    TPMS_TAGGED_PCR_SELECT	pcrProperty[MAX_PCR_PROPERTIES];	/* a tagged PCR selection */
} TPML_TAGGED_PCR_PROPERTY;

/* Table 106 - Definition of {ECC} TPML_ECC_CURVE Structure <OUT> */

typedef struct {
    UINT32		count;				/* number of curves A value of zero is allowed. */
    TPM_ECC_CURVE	eccCurves[MAX_ECC_CURVES];	/* array of ECC curve identifiers */
} TPML_ECC_CURVE ;

/* Table 107 - Definition of TPMU_CAPABILITIES Union <OUT> */

typedef union {
    TPML_ALG_PROPERTY		algorithms;	/* TPM_CAP_ALGS */
    TPML_HANDLE			handles;	/* TPM_CAP_HANDLES */
    TPML_CCA			command;	/* TPM_CAP_COMMANDS */
    TPML_CC			ppCommands;	/* TPM_CAP_PP_COMMANDS */
    TPML_CC			auditCommands;	/* TPM_CAP_AUDIT_COMMANDS */
    TPML_PCR_SELECTION		assignedPCR;	/* TPM_CAP_PCRS */
    TPML_TAGGED_TPM_PROPERTY	tpmProperties;	/* TPM_CAP_TPM_PROPERTIES */
    TPML_TAGGED_PCR_PROPERTY	pcrProperties;	/* TPM_CAP_PCR_PROPERTIES */
    TPML_ECC_CURVE		eccCurves;	/* TPM_CAP_ECC_CURVES */
} TPMU_CAPABILITIES;
    
/* Table 108 - Definition of TPMS_CAPABILITY_DATA Structure <OUT> */

typedef struct {
    TPM_CAP		capability;	/* the capability */
    TPMU_CAPABILITIES	data;		/* the capability data */
} TPMS_CAPABILITY_DATA;

/* Table 109 - Definition of TPMS_CLOCK_INFO Structure */

typedef struct {
    UINT64	clock;		/* time in milliseconds during which the TPM has been powered */
    UINT32	resetCount;	/* number of occurrences of TPM Reset since the last TPM2_Clear() */
    UINT32	restartCount;	/* number of times that TPM2_Shutdown() or _TPM_Hash_Start have
				   occurred since the last TPM Reset or TPM2_Clear(). */
    TPMI_YES_NO	safe;		/* no value of Clock greater than the current value of Clock has
				   been previously reported by the TPM */
} TPMS_CLOCK_INFO;

/* Table 110 - Definition of TPMS_TIME_INFO Structure */

typedef struct {
    UINT64		time;		/* time in milliseconds since the last _TPM_Init() or TPM2_Startup() */
    TPMS_CLOCK_INFO	clockInfo;	/* a structure containing the clock information */
} TPMS_TIME_INFO;

/* Table 111 - Definition of TPMS_TIME_ATTEST_INFO Structure <OUT> */

typedef struct {
    TPMS_TIME_INFO	time;			/* the Time, clock, resetCount, restartCount, and
						   Safe indicator */
    UINT64		firmwareVersion;	/* a TPM vendor-specific value indicating the
						   version number of the firmware */
} TPMS_TIME_ATTEST_INFO;

/* Table 112 - Definition of TPMS_CERTIFY_INFO Structure <OUT> */

typedef struct {
    TPM2B_NAME	name;		/* Name of the certified object */
    TPM2B_NAME	qualifiedName;	/* Qualified Name of the certified object */
} TPMS_CERTIFY_INFO;

/* Table 113 - Definition of TPMS_QUOTE_INFO Structure <OUT> */

typedef struct {
    TPML_PCR_SELECTION	pcrSelect;	/* information on algID, PCR selected and digest */
    TPM2B_DIGEST	pcrDigest;	/* digest of the selected PCR using the hash of the signing key */
} TPMS_QUOTE_INFO;

/* Table 114 - Definition of TPMS_COMMAND_AUDIT_INFO Structure <OUT> */

typedef struct {
    UINT64		auditCounter;	/* the monotonic audit counter */
    TPM_ALG_ID		digestAlg;	/* hash algorithm used for the command audit */
    TPM2B_DIGEST	auditDigest;	/* the current value of the audit digest */
    TPM2B_DIGEST	commandDigest;	/* digest of the command codes being audited using digestAlg */
} TPMS_COMMAND_AUDIT_INFO;

/* Table 115 - Definition of TPMS_SESSION_AUDIT_INFO Structure <OUT> */

typedef struct {
    TPMI_YES_NO		exclusiveSession;	/* current exclusive status of the session  */
    TPM2B_DIGEST	sessionDigest;		/* the current value of the session audit digest */
} TPMS_SESSION_AUDIT_INFO;

/* Table 116 - Definition of TPMS_CREATION_INFO Structure <OUT> */

typedef struct {
    TPM2B_NAME		objectName;	/* Name of the object */
    TPM2B_DIGEST	creationHash;	/* creationHash */
} TPMS_CREATION_INFO;

/* Table 117 - Definition of TPMS_NV_CERTIFY_INFO Structure <OUT> */

typedef struct {
    TPM2B_NAME 		indexName;	/* Name of the NV Index */
    UINT16 		offset;		/* the offset parameter of TPM2_NV_Certify() */
    TPM2B_MAX_NV_BUFFER nvContents;	/* contents of the NV Index */
} TPMS_NV_CERTIFY_INFO;

/* Table 118 - Definition of (TPM_ST) TPMI_ST_ATTEST Type <OUT> */

typedef TPM_ST TPMI_ST_ATTEST;

/*  Table 119 - Definition of TPMU_ATTEST Union <OUT> */

typedef union {
    TPMS_CERTIFY_INFO		certify;	/* TPM_ST_ATTEST_CERTIFY */
    TPMS_CREATION_INFO		creation;	/* TPM_ST_ATTEST_CREATION */
    TPMS_QUOTE_INFO		quote;		/* TPM_ST_ATTEST_QUOTE */
    TPMS_COMMAND_AUDIT_INFO	commandAudit;	/* TPM_ST_ATTEST_COMMAND_AUDIT */
    TPMS_SESSION_AUDIT_INFO	sessionAudit;	/* TPM_ST_ATTEST_SESSION_AUDIT */
    TPMS_TIME_ATTEST_INFO	time;		/* TPM_ST_ATTEST_TIME */
    TPMS_NV_CERTIFY_INFO	nv;		/* TPM_ST_ATTEST_NV */
} TPMU_ATTEST;

/* Table 120 - Definition of TPMS_ATTEST Structure <OUT> */

typedef struct {
    TPM_GENERATED	magic;			/* the indication that this structure was created by
						   a TPM (always TPM_GENERATED_VALUE) */
    TPMI_ST_ATTEST	type;			/* type of the attestation structure */
    TPM2B_NAME		qualifiedSigner;	/* Qualified Name of the signing key */
    TPM2B_DATA		extraData;		/* external information supplied by caller */
    TPMS_CLOCK_INFO	clockInfo;		/* Clock, resetCount, restartCount, and Safe */
    UINT64		firmwareVersion;	/* TPM-vendor-specific value identifying the version
						   number of the firmware */
    TPMU_ATTEST		attested;		/* the type-specific attestation information */
} TPMS_ATTEST;

/* Table 121 - Definition of TPM2B_ATTEST Structure <OUT> */

typedef struct {
    UINT16	size;					/* size of the attestationData structure */
    BYTE	attestationData[sizeof(TPMS_ATTEST)];	/* the signed structure */
} ATTEST_2B;

typedef union {
    ATTEST_2B t;
    TPM2B     b;
} TPM2B_ATTEST;

/* Table 122 - Definition of TPMS_AUTH_COMMAND Structure <IN> */

typedef struct {
    TPMI_SH_AUTH_SESSION	sessionHandle;		/* the session handle */
    TPM2B_NONCE			nonce;			/* the session nonce, may be the Empty Buffer */
    TPMA_SESSION		sessionAttributes;	/* the session attributes */
    TPM2B_AUTH			hmac;			/* either an HMAC, a password, or an EmptyAuth */
} TPMS_AUTH_COMMAND;

/* Table 123 - Definition of TPMS_AUTH_RESPONSE Structure <OUT> */

typedef struct {
    TPM2B_NONCE		nonce;			/* the session nonce, may be the Empty Buffer */
    TPMA_SESSION	sessionAttributes;	/* the session attributes */
    TPM2B_AUTH		hmac;			/* either an HMAC or an EmptyAuth */
} TPMS_AUTH_RESPONSE;

/* Table 124 - Definition of {AES} (TPM_KEY_BITS) TPMI_!ALG.S_KEY_BITS Type */

typedef TPM_KEY_BITS TPMI_AES_KEY_BITS;
typedef TPM_KEY_BITS TPMI_SM4_KEY_BITS;
typedef TPM_KEY_BITS TPMI_CAMELLIA_KEY_BITS;

/* Table 125 - Definition of TPMU_SYM_KEY_BITS Union */

typedef union {
#ifdef TPM_ALG_AES
    TPMI_AES_KEY_BITS		aes;	/* TPM_ALG_AES */
#endif
#ifdef TPM_ALG_SM4
    TPMI_SM4_KEY_BITS		sm4;	/* TPM_ALG_SM4 */
#endif
#ifdef TPM_ALG_CAMELLIA
    TPMI_CAMELLIA_KEY_BITS 	camellia;	/* TPM_ALG_CAMELLIA */
#endif
#ifdef TPM_ALG_XOR
    TPMI_ALG_HASH		exclusiveOr;	/* TPM_ALG_XOR	overload for using xor */
#endif
    TPM_KEY_BITS		sym;	/* when selector may be any of the symmetric block ciphers */
} TPMU_SYM_KEY_BITS;

/* Table 126 - Definition of TPMU_SYM_MODE Union */

typedef union {
#ifdef TPM_ALG_AES
    TPMI_ALG_SYM_MODE	aes;		/* TPM_ALG_AES */
#endif
#ifdef TPM_ALG_SM4
    TPMI_ALG_SYM_MODE	sm4;		/* TPM_ALG_SM4 */
#endif
#ifdef TPM_ALG_CAMELLIA
    TPMI_ALG_SYM_MODE	camellia;	/* TPM_ALG_CAMELLIA */
#endif
    TPMI_ALG_SYM_MODE	sym;		/* when selector may be any of the symmetric block ciphers */
} TPMU_SYM_MODE;

/* Table 127 - xDefinition of TPMU_SYM_DETAILS Union */

/* Table 128 - Definition of TPMT_SYM_DEF Structure */

typedef struct {
    TPMI_ALG_SYM	algorithm;	/* indicates a symmetric algorithm */
    TPMU_SYM_KEY_BITS 	keyBits;	/* a supported key size */
    TPMU_SYM_MODE 	mode;		/* the mode for the key */
} TPMT_SYM_DEF;

/* Table 129 - Definition of TPMT_SYM_DEF_OBJECT Structure */

typedef struct {
    TPMI_ALG_SYM_OBJECT	algorithm;	/* selects a symmetric block cipher */
    TPMU_SYM_KEY_BITS	keyBits;	/* the key size */
    TPMU_SYM_MODE	mode;		/* default mode */
} TPMT_SYM_DEF_OBJECT;

/* Table 130 - Definition of TPM2B_SYM_KEY Structure */

typedef struct {
    UINT16	size;				/* size, in octets, of the buffer containing the key; may be zero */
    BYTE	buffer [MAX_SYM_KEY_BYTES]; 	/* the key */
} SYM_KEY_2B;

typedef union {
    SYM_KEY_2B t;
    TPM2B      b;
} TPM2B_SYM_KEY;

/* Table 131 - Definition of TPMS_SYMCIPHER_PARMS Structure */

typedef struct {
    TPMT_SYM_DEF_OBJECT	sym;	/* a symmetric block cipher */
} TPMS_SYMCIPHER_PARMS;

/* Table 132 - Definition of TPM2B_SENSITIVE_DATA Structure */

typedef struct {
    UINT16	size;
    BYTE	buffer[MAX_SYM_DATA];	/* the keyed hash private data structure */
} SENSITIVE_DATA_2B;

typedef union {
    SENSITIVE_DATA_2B t;
    TPM2B             b;
} TPM2B_SENSITIVE_DATA;

/* Table 133 - Definition of TPMS_SENSITIVE_CREATE Structure <IN> */

typedef struct {
    TPM2B_AUTH			userAuth;	/* the USER auth secret value */
    TPM2B_SENSITIVE_DATA	data;		/* data to be sealed */
} TPMS_SENSITIVE_CREATE;

/* Table 134 - Definition of TPM2B_SENSITIVE_CREATE Structure <IN, S> */

typedef struct {
    UINT16			size;		/* size of sensitive in octets (may not be zero) */
    TPMS_SENSITIVE_CREATE	sensitive;	/* data to be sealed or a symmetric key value. */
} SENSITIVE_CREATE_2B;

typedef union {
    SENSITIVE_CREATE_2B t;
    TPM2B               b;
} TPM2B_SENSITIVE_CREATE;

/* Table 135 - Definition of TPMS_SCHEME_HASH Structure */

typedef struct {
    TPMI_ALG_HASH	hashAlg;	/* the hash algorithm used to digest the message */
} TPMS_SCHEME_HASH;

/* Table 136 - Definition of {ECC} TPMS_SCHEME_ECDAA Structure */

typedef struct {
    TPMI_ALG_HASH	hashAlg;	/* the hash algorithm used to digest the message */
    UINT16		count;		/* the counter value that is used between TPM2_Commit() and the sign operation */
} TPMS_SCHEME_ECDAA;
    
/* Table 137 - Definition of (TPM_ALG_ID) TPMI_ALG_KEYEDHASH_SCHEME Type */

typedef TPM_ALG_ID TPMI_ALG_KEYEDHASH_SCHEME;

/* Table 138 - Definition of Types for HMAC_SIG_SCHEME */

typedef TPMS_SCHEME_HASH	TPMS_SCHEME_HMAC;

/* Table 139 - Definition of TPMS_SCHEME_XOR Structure */

typedef struct {
    TPMI_ALG_HASH	hashAlg;	/* the hash algorithm used to digest the message */
    TPMI_ALG_KDF	kdf;		/* the key derivation function */
} TPMS_SCHEME_XOR;

/* Table 140 - Definition of TPMU_SCHEME_KEYEDHASH Union <IN/OUT, S> */

typedef union {
#ifdef TPM_ALG_HMAC
    TPMS_SCHEME_HMAC	hmac;	/* TPM_ALG_HMAC	the "signing" scheme */
#endif
#ifdef TPM_ALG_XOR
    TPMS_SCHEME_XOR	exclusiveOr;	/* TPM_ALG_XOR 	the "obfuscation" scheme */
#endif
} TPMU_SCHEME_KEYEDHASH;

/* Table 141 - Definition of TPMT_KEYEDHASH_SCHEME Structure */

typedef struct {
    TPMI_ALG_KEYEDHASH_SCHEME	scheme;		/* selects the scheme */
    TPMU_SCHEME_KEYEDHASH	details;	/* the scheme parameters */
} TPMT_KEYEDHASH_SCHEME;

/* Table 142 - Definition of {RSA} Types for RSA Signature Schemes */

typedef TPMS_SCHEME_HASH 	TPMS_SIG_SCHEME_RSASSA;			
typedef TPMS_SCHEME_HASH 	TPMS_SIG_SCHEME_RSAPSS;

/* Table 143 - Definition of {ECC} Types for ECC Signature Schemes */

typedef TPMS_SCHEME_HASH 	TPMS_SIG_SCHEME_ECDSA;			
typedef TPMS_SCHEME_HASH	TPMS_SIG_SCHEME_SM2;			
typedef TPMS_SCHEME_HASH 	TPMS_SIG_SCHEME_ECSCHNORR;

typedef TPMS_SCHEME_ECDAA	TPMS_SIG_SCHEME_ECDAA;

/* Table 144 - Definition of TPMU_SIG_SCHEME Union <IN/OUT, S> */

typedef union {
#ifdef TPM_ALG_RSASSA
    TPMS_SIG_SCHEME_RSASSA	rsassa;		/* TPM_ALG_RSASSA	the RSASSA-PKCS1v1_5 scheme */
#endif
#ifdef TPM_ALG_RSAPSS
    TPMS_SIG_SCHEME_RSAPSS	rsapss;		/* TPM_ALG_RSAPSS	the RSASSA-PSS scheme */
#endif
#ifdef TPM_ALG_ECDSA
    TPMS_SIG_SCHEME_ECDSA	ecdsa;		/* TPM_ALG_ECDSA	the ECDSA scheme */
#endif
#ifdef TPM_ALG_ECDAA
    TPMS_SIG_SCHEME_ECDAA	ecdaa;		/* TPM_ALG_ECDAA	the ECDAA scheme */
#endif
#ifdef TPM_ALG_SM2
    TPMS_SIG_SCHEME_SM2		sm2;		/* TPM_ALG_SM2		ECDSA from SM2 */
#endif
#ifdef TPM_ALG_ECSCHNORR
    TPMS_SIG_SCHEME_ECSCHNORR	ecschnorr;	/* TPM_ALG_ECSCHNORR	the EC Schnorr */
#endif
#ifdef TPM_ALG_HMAC
    TPMS_SCHEME_HMAC		hmac;		/* TPM_ALG_HMAC		the HMAC scheme */
#endif
    TPMS_SCHEME_HASH		any;		/* selector that allows access to digest for any signing scheme */
} TPMU_SIG_SCHEME;

/* Table 145 - Definition of TPMT_SIG_SCHEME Structure */

typedef struct {
    TPMI_ALG_SIG_SCHEME	scheme;		/* scheme selector */
    TPMU_SIG_SCHEME	details;	/* scheme parameters */
} TPMT_SIG_SCHEME;

/* Table 146 - Definition of Types for {RSA} Encryption Schemes */

typedef TPMS_SCHEME_HASH	TPMS_ENC_SCHEME_OAEP; 	/* schemes that only need a hash */ 

typedef TPMS_EMPTY		TPMS_ENC_SCHEME_RSAES;	/* schemes that need nothing */

/* Table 147 - Definition of Types for {ECC} ECC Key Exchange */

typedef TPMS_SCHEME_HASH	TPMS_KEY_SCHEME_ECDH; 	/* schemes that only need a hash */ 
typedef TPMS_SCHEME_HASH	TPMS_KEY_SCHEME_ECMQV; 	/* schemes that only need a hash */ 

/* Table 148 - Definition of Types for KDF Schemes, hash-based key- or mask-generation functions */

typedef TPMS_SCHEME_HASH	TPMS_SCHEME_MGF1; 
typedef TPMS_SCHEME_HASH	TPMS_SCHEME_KDF1_SP800_56A;
typedef TPMS_SCHEME_HASH	TPMS_SCHEME_KDF2;
typedef TPMS_SCHEME_HASH	TPMS_SCHEME_KDF1_SP800_108;

/* Table 149 - Definition of TPMU_KDF_SCHEME Union <IN/OUT, S> */

typedef union {
#ifdef TPM_ALG_MGF1
    TPMS_SCHEME_MGF1		mgf1;		/* TPM_ALG_MGF1 */
#endif
#ifdef TPM_ALG_KDF1_SP800_56A
    TPMS_SCHEME_KDF1_SP800_56A	kdf1_sp800_56a;	/* TPM_ALG_KDF1_SP800_56A */
#endif
#ifdef TPM_ALG_KDF2
    TPMS_SCHEME_KDF2		kdf2;		/* TPM_ALG_KDF2 */
#endif
#ifdef TPM_ALG_KDF1_SP800_108
    TPMS_SCHEME_KDF1_SP800_108	kdf1_sp800_108;	/* TPM_ALG_KDF1_SP800_108 */
#endif
} TPMU_KDF_SCHEME;

/* Table 150 - Definition of TPMT_KDF_SCHEME Structure */

typedef struct {
    TPMI_ALG_KDF	scheme;		/* scheme selector */
    TPMU_KDF_SCHEME	details;	/* scheme parameters */
} TPMT_KDF_SCHEME;
 
/* Table 151 - Definition of (TPM_ALG_ID) TPMI_ALG_ASYM_SCHEME Type <> */

typedef TPM_ALG_ID 		TPMI_ALG_ASYM_SCHEME;

/* Table 152 - Definition of TPMU_ASYM_SCHEME Union */

typedef union {
#ifdef TPM_ALG_ECDH
    TPMS_KEY_SCHEME_ECDH	ecdh;		/* TPM_ALG_ECDH */
#endif
#ifdef TPM_ALG_ECMQV
    TPMS_KEY_SCHEME_ECMQV	ecmqvh;		/* TPM_ALG_ECMQV */
#endif
#ifdef TPM_ALG_RSASSA
    TPMS_SIG_SCHEME_RSASSA	rsassa;		/* TPM_ALG_RSASSA */
#endif
#ifdef TPM_ALG_RSAPSS
    TPMS_SIG_SCHEME_RSAPSS	rsapss;		/* TPM_ALG_RSAPSS */
#endif
#ifdef TPM_ALG_ECDSA
    TPMS_SIG_SCHEME_ECDSA	ecdsa;		/* TPM_ALG_ECDSA */
#endif
#ifdef TPM_ALG_ECDAA
    TPMS_SIG_SCHEME_ECDAA	ecdaa;		/* TPM_ALG_ECDAA */
#endif
#ifdef TPM_ALG_SM2
    TPMS_SIG_SCHEME_SM2		sm2;		/* TPM_ALG_SM2 */
#endif
#ifdef TPM_ALG_ECSCHNORR
    TPMS_SIG_SCHEME_ECSCHNORR	ecschnorr;	/* TPM_ALG_ECSCHNORR */
#endif
#ifdef TPM_ALG_RSAES
    TPMS_ENC_SCHEME_RSAES	rsaes;		/* TPM_ALG_RSAES */
#endif
#ifdef TPM_ALG_OAEP
    TPMS_ENC_SCHEME_OAEP	oaep;		/* TPM_ALG_OAEP */
#endif
    TPMS_SCHEME_HASH		anySig;
} TPMU_ASYM_SCHEME;

/* Table 153 - Definition of TPMT_ASYM_SCHEME Structure <> */

typedef struct {
    TPMI_ALG_ASYM_SCHEME	scheme;		/* scheme selector */
    TPMU_ASYM_SCHEME		details;	/* scheme parameters */
} TPMT_ASYM_SCHEME;

/* Table 154 - Definition of (TPM_ALG_ID) {RSA} TPMI_ALG_RSA_SCHEME Type */

typedef TPM_ALG_ID TPMI_ALG_RSA_SCHEME;

/* Table 155 - Definition of {RSA} TPMT_RSA_SCHEME Structure */

typedef struct {
    TPMI_ALG_RSA_SCHEME	scheme;		/* scheme selector */
    TPMU_ASYM_SCHEME	details;	/* scheme parameters */
} TPMT_RSA_SCHEME;
    
/* Table 156 - Definition of (TPM_ALG_ID) {RSA} TPMI_ALG_RSA_DECRYPT Type */

typedef TPM_ALG_ID TPMI_ALG_RSA_DECRYPT;

/* Table 157 - Definition of {RSA} TPMT_RSA_DECRYPT Structure */

typedef struct {
    TPMI_ALG_RSA_DECRYPT	scheme;		/* scheme selector */
    TPMU_ASYM_SCHEME		details;	/* scheme parameters */
} TPMT_RSA_DECRYPT;
    
/* Table 158 - Definition of {RSA} TPM2B_PUBLIC_KEY_RSA Structure */

typedef struct {
    UINT16	size;				/* size of the buffer */
    BYTE	buffer[MAX_RSA_KEY_BYTES];	/* Value */
} PUBLIC_KEY_RSA_2B;

typedef union {
    PUBLIC_KEY_RSA_2B t;
    TPM2B             b;
} TPM2B_PUBLIC_KEY_RSA;

/* Table 159 - Definition of {RSA} (TPM_KEY_BITS) TPMI_RSA_KEY_BITS Type */

typedef TPM_KEY_BITS TPMI_RSA_KEY_BITS;

/* Table 160 - Definition of {RSA} TPM2B_PRIVATE_KEY_RSA Structure */

typedef struct {
    UINT16	size;
    BYTE	buffer[MAX_RSA_KEY_BYTES/2];	
} PRIVATE_KEY_RSA_2B;

typedef union {
    PRIVATE_KEY_RSA_2B t;
    TPM2B              b;
} TPM2B_PRIVATE_KEY_RSA;

/* Table 161 - Definition of {ECC} TPM2B_ECC_PARAMETER Structure */

typedef struct {
    UINT16	size;				/* size of the buffer */
    BYTE	buffer[MAX_ECC_KEY_BYTES];	/* the parameter data */
} ECC_PARAMETER_2B;

typedef union {
    ECC_PARAMETER_2B t;
    TPM2B	     b;
} TPM2B_ECC_PARAMETER;

/* Table 162 - Definition of {ECC} TPMS_ECC_POINT Structure */

typedef struct {
    TPM2B_ECC_PARAMETER	x;	/* X coordinate */
    TPM2B_ECC_PARAMETER	y;	/* Y coordinate */
} TPMS_ECC_POINT;
    
/* Table 163 - Definition of {ECC} TPM2B_ECC_POINT Structure */

typedef struct {
    UINT16		size;	/* size of the remainder of this structure */
    TPMS_ECC_POINT	point;	/* coordinates */
} ECC_POINT_2B;

typedef union {
    ECC_POINT_2B t;
    TPM2B        b;
} TPM2B_ECC_POINT;

/* Table 164 - Definition of (TPM_ALG_ID) {ECC} TPMI_ALG_ECC_SCHEME Type */

typedef TPM_ALG_ID TPMI_ALG_ECC_SCHEME;

/* Table 165 - Definition of {ECC} (TPM_ECC_CURVE) TPMI_ECC_CURVE Type */

typedef TPM_ECC_CURVE TPMI_ECC_CURVE;
    
/* Table 166 - Definition of (TPMT_SIG_SCHEME) {ECC} TPMT_ECC_SCHEME Structure */

typedef struct {
    TPMI_ALG_ECC_SCHEME 	scheme;		/* scheme selector */
    TPMU_ASYM_SCHEME		details;	/* scheme parameters */
} TPMT_ECC_SCHEME;
   
/* Table 167 - Definition of {ECC} TPMS_ALGORITHM_DETAIL_ECC Structure <OUT> */

typedef struct {
    TPM_ECC_CURVE	curveID;	/* identifier for the curve */
    UINT16		keySize;	/* Size in bits of the key */
    TPMT_KDF_SCHEME	kdf;		/* the default KDF and hash algorithm used in secret sharing operations */
    TPMT_ECC_SCHEME	sign;		/* If not TPM_ALG_NULL, this is the mandatory signature
					   scheme that is required to be used with this curve. */
    TPM2B_ECC_PARAMETER	p;		/* Fp (the modulus) */
    TPM2B_ECC_PARAMETER	a;		/* coefficient of the linear term in the curve equation */
    TPM2B_ECC_PARAMETER	b;		/* constant term for curve equation */
    TPM2B_ECC_PARAMETER	gX;		/* x coordinate of base point G */
    TPM2B_ECC_PARAMETER	gY;		/* y coordinate of base point G */
    TPM2B_ECC_PARAMETER	n;		/* order of G */
    TPM2B_ECC_PARAMETER	h;		/* cofactor (a size of zero indicates a cofactor of 1) */
} TPMS_ALGORITHM_DETAIL_ECC;
    
/* Table 168 - Definition of {RSA} TPMS_SIGNATURE_RSA Structure */

typedef struct {
    TPMI_ALG_HASH		hash;	/* the hash algorithm used to digest the message TPM_ALG_NULL is not allowed. */
    TPM2B_PUBLIC_KEY_RSA	sig;	/* The signature is the size of a public key. */
} TPMS_SIGNATURE_RSA;
    
/* Table 169 - Definition of Types for {RSA} Signature */

typedef TPMS_SIGNATURE_RSA	TPMS_SIGNATURE_RSASSA;
typedef TPMS_SIGNATURE_RSA	TPMS_SIGNATURE_RSAPSS;
    
/* Table 170 - Definition of {ECC} TPMS_SIGNATURE_ECC Structure */

typedef struct {
    TPMI_ALG_HASH	hash;	/* the hash algorithm used in the signature process TPM_ALG_NULL is not allowed. */
    TPM2B_ECC_PARAMETER	signatureR;
    TPM2B_ECC_PARAMETER	signatureS;
} TPMS_SIGNATURE_ECC;
    
/* Table 171 - Definition of Types for {ECC} TPMS_SIGNATURE_ECC */

typedef TPMS_SIGNATURE_ECC	TPMS_SIGNATURE_ECDSA;
typedef TPMS_SIGNATURE_ECC	TPMS_SIGNATURE_ECDAA;
typedef TPMS_SIGNATURE_ECC	TPMS_SIGNATURE_SM2;
typedef TPMS_SIGNATURE_ECC	TPMS_SIGNATURE_ECSCHNORR;

/* Table 172 - Definition of TPMU_SIGNATURE Union <IN/OUT, S> */

typedef union {
#ifdef TPM_ALG_RSASSA
    TPMS_SIGNATURE_RSASSA	rsassa;			/* TPM_ALG_RSASSA */
#endif
#ifdef TPM_ALG_RSAPSS
    TPMS_SIGNATURE_RSAPSS	rsapss;			/* TPM_ALG_RSAPSS */
#endif
#ifdef TPM_ALG_ECDSA
    TPMS_SIGNATURE_ECDSA	ecdsa;			/* TPM_ALG_ECDSA */
#endif
#ifdef TPM_ALG_ECDAA
    TPMS_SIGNATURE_ECDSA	ecdaa;			/* TPM_ALG_ECDAA */
#endif
#ifdef TPM_ALG_SM2
    TPMS_SIGNATURE_ECDSA	sm2;			/* TPM_ALG_SM2 */
#endif
#ifdef TPM_ALG_ECSCHNORR
    TPMS_SIGNATURE_ECDSA	ecschnorr;		/* TPM_ALG_ECSCHNORR */
#endif
#ifdef TPM_ALG_HMAC
    TPMT_HA			hmac;			/* TPM_ALG_HMAC */
#endif
    TPMS_SCHEME_HASH		any;			/* used to access the hash */
} TPMU_SIGNATURE;

/* Table 173 - Definition of TPMT_SIGNATURE Structure */

typedef struct {
    TPMI_ALG_SIG_SCHEME	sigAlg;		/* selector of the algorithm used to construct the signature */
    TPMU_SIGNATURE	signature;	/* This shall be the actual signature information. */
} TPMT_SIGNATURE;
    
/* Table 174 - Definition of TPMU_ENCRYPTED_SECRET Union <S> */

typedef union {
#ifdef TPM_ALG_ECC
    BYTE	ecc[sizeof(TPMS_ECC_POINT)];		/* TPM_ALG_ECC */
#endif
#ifdef TPM_ALG_RSA
    BYTE	rsa[MAX_RSA_KEY_BYTES];			/* TPM_ALG_RSA */
#endif
#ifdef TPM_ALG_SYMCIPHER
    BYTE	symmetric[sizeof(TPM2B_DIGEST)];	/* TPM_ALG_SYMCIPHER */
#endif
#ifdef TPM_ALG_KEYEDHASH
    BYTE	keyedHash[sizeof(TPM2B_DIGEST)];	/* TPM_ALG_KEYEDHASH */
#endif
} TPMU_ENCRYPTED_SECRET;

/* Table 175 - Definition of TPM2B_ENCRYPTED_SECRET Structure */

typedef struct {
    UINT16	size;					/* size of the secret value */
    BYTE	secret[sizeof(TPMU_ENCRYPTED_SECRET)];	/* secret */
} ENCRYPTED_SECRET_2B;

typedef union {
    ENCRYPTED_SECRET_2B t;
    TPM2B               b;
} TPM2B_ENCRYPTED_SECRET;

/* Table 176 - Definition of (TPM_ALG_ID) TPMI_ALG_PUBLIC Type */

typedef TPM_ALG_ID TPMI_ALG_PUBLIC;

/* Table 177 - Definition of TPMU_PUBLIC_ID Union <IN/OUT, S> */

typedef union {
#ifdef TPM_ALG_KEYEDHASH
    TPM2B_DIGEST		keyedHash;	/* TPM_ALG_KEYEDHASH */
#endif
#ifdef TPM_ALG_SYMCIPHER
    TPM2B_DIGEST		sym;		/* TPM_ALG_SYMCIPHER */
#endif
#ifdef TPM_ALG_RSA
    TPM2B_PUBLIC_KEY_RSA	rsa;		/* TPM_ALG_RSA */
#endif
#ifdef TPM_ALG_ECC
    TPMS_ECC_POINT		ecc;		/* TPM_ALG_ECC */
#endif
} TPMU_PUBLIC_ID;

/* Table 178 - Definition of TPMS_KEYEDHASH_PARMS Structure */

typedef struct {
    TPMT_KEYEDHASH_SCHEME	scheme;	/* Indicates the signing method used for a keyedHash signing object */
} TPMS_KEYEDHASH_PARMS;
 
/* Table 179 - Definition of TPMS_ASYM_PARMS Structure <> */

typedef struct {
    TPMT_SYM_DEF_OBJECT	symmetric;	/* the companion symmetric algorithm for a restricted decryption key */
    TPMT_ASYM_SCHEME	scheme;		/* for a key with the sign attribute SET, a valid signing scheme for the key type */
} TPMS_ASYM_PARMS;
 
/* Table 180 - Definition of {RSA} TPMS_RSA_PARMS Structure */

typedef struct {
    TPMT_SYM_DEF_OBJECT	symmetric;	/* for a restricted decryption key, shall be set to a supported symmetric algorithm, key size, and mode. */
    TPMT_RSA_SCHEME	scheme;		/* for an unrestricted signing key, shall be either TPM_ALG_RSAPSS TPM_ALG_RSASSA or TPM_ALG_NULL */
    TPMI_RSA_KEY_BITS 	keyBits;	/* number of bits in the public modulus */
    UINT32		exponent;	/* the public exponent  */
} TPMS_RSA_PARMS;

/* Table 181 - Definition of {ECC} TPMS_ECC_PARMS Structure */

typedef struct {
    TPMT_SYM_DEF_OBJECT	symmetric;	/* for a restricted decryption key, shall be set to a supported symmetric algorithm, key size. and mode. */
    TPMT_ECC_SCHEME	scheme;		/* If the sign attribute of the key is SET, then this shall be a valid signing scheme. */
    TPMI_ECC_CURVE	curveID;	/* ECC curve ID */
    TPMT_KDF_SCHEME	kdf;		/* an optional key derivation scheme for generating a symmetric key from a Z value */
} TPMS_ECC_PARMS;

/* Table 182 - Definition of TPMU_PUBLIC_PARMS Union <IN/OUT, S> */

typedef union {
#ifdef TPM_ALG_KEYEDHASH
    TPMS_KEYEDHASH_PARMS	keyedHashDetail;	/* TPM_ALG_KEYEDHASH */
#endif
#ifdef TPM_ALG_SYMCIPHER
    TPMS_SYMCIPHER_PARMS	symDetail;		/* TPM_ALG_SYMCIPHER */
#endif
#ifdef TPM_ALG_RSA
    TPMS_RSA_PARMS		rsaDetail;		/* TPM_ALG_RSA */
#endif
#ifdef TPM_ALG_ECC
    TPMS_ECC_PARMS		eccDetail;		/* TPM_ALG_ECC */
#endif
    TPMS_ASYM_PARMS		asymDetail;		/* common scheme structure for RSA and ECC keys */
} TPMU_PUBLIC_PARMS;

/* Table 183 - Definition of TPMT_PUBLIC_PARMS Structure */

typedef struct {
    TPMI_ALG_PUBLIC	type;		/* the algorithm to be tested */
    TPMU_PUBLIC_PARMS	parameters;	/* the algorithm details */
} TPMT_PUBLIC_PARMS;
 
/* Table 184 - Definition of TPMT_PUBLIC Structure */

typedef struct {
    TPMI_ALG_PUBLIC	type;			/* "algorithm" associated with this object */
    TPMI_ALG_HASH	nameAlg;		/* algorithm used for computing the Name of the object */
    TPMA_OBJECT		objectAttributes;	/* attributes that, along with type, determine the manipulations of this object */
    TPM2B_DIGEST	authPolicy;		/* optional policy for using this key */
    TPMU_PUBLIC_PARMS	parameters;		/* the algorithm or structure details */
    TPMU_PUBLIC_ID	unique;			/* the unique identifier of the structure */
} TPMT_PUBLIC;
 
/* Table 185 - Definition of TPM2B_PUBLIC Structure */

typedef struct {
    UINT16	size;		/* size of publicArea */
    TPMT_PUBLIC	publicArea;	/* the public area  */
} PUBLIC_2B;

typedef union {
    PUBLIC_2B t;
    TPM2B     b;
} TPM2B_PUBLIC;

/* Table 186 - Definition of TPM2B_PRIVATE_VENDOR_SPECIFIC Structure<> */

typedef struct {
    UINT16	size;
    BYTE	buffer[PRIVATE_VENDOR_SPECIFIC_BYTES];	
} PRIVATE_VENDOR_SPECIFIC_2B;

typedef union {
    PRIVATE_VENDOR_SPECIFIC_2B t;
    TPM2B                      b;
} TPM2B_PRIVATE_VENDOR_SPECIFIC;

/* Table 187 - Definition of TPMU_SENSITIVE_COMPOSITE Union <IN/OUT, S> */

typedef union {
#ifdef TPM_ALG_RSA
    TPM2B_PRIVATE_KEY_RSA		rsa;	/* TPM_ALG_RSA a prime factor of the public key */
#endif
#ifdef TPM_ALG_ECC
    TPM2B_ECC_PARAMETER			ecc;	/* TPM_ALG_ECC the integer private key */
#endif
#ifdef TPM_ALG_KEYEDHASH
    TPM2B_SENSITIVE_DATA		bits;	/* TPM_ALG_KEYEDHASH the private data */
#endif
#ifdef TPM_ALG_SYMCIPHER
    TPM2B_SYM_KEY			sym;	/* TPM_ALG_SYMCIPHER the symmetric key */
#endif
    TPM2B_PRIVATE_VENDOR_SPECIFIC	any;	/* vendor-specific size for key storage */
} TPMU_SENSITIVE_COMPOSITE;

/* Table 188 - Definition of TPMT_SENSITIVE Structure */

typedef struct {
    TPMI_ALG_PUBLIC		sensitiveType;	/* identifier for the sensitive area  */
    TPM2B_AUTH			authValue;	/* user authorization data */
    TPM2B_DIGEST		seedValue;	/* for asymmetric key object, the optional protection seed; for other objects, the obfuscation value */
    TPMU_SENSITIVE_COMPOSITE	sensitive;	/* the type-specific private data */
} TPMT_SENSITIVE;
 
/* Table 189 - Definition of TPM2B_SENSITIVE Structure <IN/OUT> */

typedef struct {
    UINT16		size;		/* size of the private structure */
    TPMT_SENSITIVE	sensitiveArea;	/* an unencrypted sensitive area */
} SENSITIVE_2B;

typedef union {
    SENSITIVE_2B t;
    TPM2B        b;
} TPM2B_SENSITIVE;

/* Table 190 - Definition of _PRIVATE Structure <> */

typedef struct {
    TPM2B_DIGEST	integrityOuter;
    TPM2B_DIGEST	integrityInner;	/* could also be a TPM2B_IV */
    TPMT_SENSITIVE	sensitive;	/* the sensitive area */
} _PRIVATE;
 
/* Table 191 - Definition of TPM2B_PRIVATE Structure <IN/OUT, S> */

typedef struct {
    UINT16	size;				/* size of the private structure */
    BYTE	buffer[sizeof(_PRIVATE)];	/* an encrypted private area */
} PRIVATE_2B;

typedef union {
    PRIVATE_2B t;
    TPM2B      b;
} TPM2B_PRIVATE;

/* Table 192 - Definition of _ID_OBJECT Structure <> */

typedef struct {
    TPM2B_DIGEST	integrityHMAC;	/* HMAC using the nameAlg of the storage key on the target TPM */
    TPM2B_DIGEST	encIdentity;	/* credential protector information returned if name matches the referenced object */
} _ID_OBJECT;
 
/* Table 193 - Definition of TPM2B_ID_OBJECT Structure <IN/OUT> */

typedef struct {
    UINT16	size;				/* size of the credential structure */
    BYTE	credential[sizeof(_ID_OBJECT)];	/* an encrypted credential area */
} ID_OBJECT_2B;

typedef union {
    ID_OBJECT_2B t;
    TPM2B        b;
} TPM2B_ID_OBJECT;

/* Table 194 - Definition of (UINT32) TPM_NV_INDEX Bits <> */

#if defined TPM_BITFIELD_LE

typedef union {
    struct {
	unsigned int index : 24;    	/* 23:0	 The Index of the NV location */
	unsigned int RH_NV : 8;    	/* 31:24 constant value of TPM_HT_NV_INDEX indicating the NV Index range */
    };
    UINT32 val;
} TPM_NV_INDEX;

#elif defined TPM_BITFIELD_BE

typedef union {
    struct {
	unsigned int RH_NV : 8;    	/* 31:24 constant value of TPM_HT_NV_INDEX indicating the NV Index range */
	unsigned int index : 24;    	/* 23:0	 The Index of the NV location */
    };
    UINT32 val;
} TPM_NV_INDEX;

#else 

typedef uint32_t TPM_NV_INDEX;

#define TPM_NV_INDEX_INDEX	0x00ffffff
#define TPM_NV_INDEX_RH_NV	0xff000000

#endif

/* Table 195 - Definition of TPM_NT Constants */

#define TPM_NT_ORDINARY	0x0	/* Ordinary - contains data that is opaque to the TPM that can only be modified using TPM2_NV_Write(). */
#define TPM_NT_COUNTER	0x1	/* Counter - contains an 8-octet value that is to be used as a counter and can only be modified with TPM2_NV_Increment() */
#define TPM_NT_BITS	0x2	/* Bit Field - contains an 8-octet value to be used as a bit field and can only be modified with TPM2_NV_SetBits(). */
#define TPM_NT_EXTEND	0x4	/* Extend - contains a digest-sized value used like a PCR. The Index can only be modified using TPM2_NV_Extend(). The extend will use the nameAlg of the Index. */
#define TPM_NT_PIN_FAIL	0x8	/* PIN Fail - contains a PIN limit and a PIN count that increments on a PIN authorization failure */
#define TPM_NT_PIN_PASS	0x9	/* PIN Pass - contains a PIN limit and a PIN count that increments on a PIN authorization success */


/* Table 196 - Definition of (UINT32) TPMA_NV Bits */

#if defined TPM_BITFIELD_LE

typedef union {
    struct {
	unsigned int TPMA_NV_PPWRITE		: 1; 	/* 0	The Index data can be written if Platform Authorization is provided. */
	unsigned int TPMA_NV_OWNERWRITE		: 1;	/* 1	The Index data can be written if Owner Authorization is provided. */
	unsigned int TPMA_NV_AUTHWRITE		: 1;	/* 2    Authorizations to change the Index contents that require USER role may be provided with an HMAC session or password. */
	unsigned int TPMA_NV_POLICYWRITE	: 1;	/* 3    Authorizations to change the Index contents that require USER role may be provided with a policy session. */
	unsigned int TPM_NT			: 4;	/* 7:4  The type of the index */
	unsigned int Reserved1 			: 2;	/* 9:8	shall be zero reserved for future use */
	unsigned int TPMA_NV_POLICY_DELETE	: 1;	/* 10	Index may not be deleted unless the authPolicy is satisfied. */
	unsigned int TPMA_NV_WRITELOCKED	: 1;	/* 11	Index cannot be written. */
	unsigned int TPMA_NV_WRITEALL		: 1;	/* 12   A partial write of the Index data is not allowed. The write size shall match the defined space size. */
	unsigned int TPMA_NV_WRITEDEFINE	: 1;	/* 13   TPM2_NV_WriteLock() may be used to prevent further writes to this location. */
	unsigned int TPMA_NV_WRITE_STCLEAR	: 1;	/* 14   TPM2_NV_WriteLock() may be used to prevent further writes to this location until the next TPM Reset or TPM Restart. */
	unsigned int TPMA_NV_GLOBALLOCK		: 1;	/* 15   If TPM2_NV_GlobalLock() is successful, then further writes are not permitted until the next TPM Reset or TPM Restart. */
	unsigned int TPMA_NV_PPREAD		: 1;	/* 16	The Index data can be read if Platform Authorization is provided. */
	unsigned int TPMA_NV_OWNERREAD		: 1;	/* 17	The Index data can be read if Owner Authorization is provided. */
	unsigned int TPMA_NV_AUTHREAD		: 1;	/* 18	The Index data may be read if the authValue is provided. */
	unsigned int TPMA_NV_POLICYREAD		: 1;	/* 19	The Index data may be read if the authPolicy is satisfied. */
	unsigned int Reserved2			: 5;	/* 24:20 shall be zero reserved for future use */
	unsigned int TPMA_NV_NO_DA		: 1;	/* 25	Authorization failures of the Index do not affect the DA logic */
	unsigned int TPMA_NV_ORDERLY		: 1;	/* 26	NV Index state is only required to be saved when the TPM performs an orderly shutdown */
	unsigned int TPMA_NV_CLEAR_STCLEAR	: 1;	/* 27	TPMA_NV_WRITTEN for the Index is CLEAR by TPM Reset or TPM Restart. */
	unsigned int TPMA_NV_READLOCKED		: 1;	/* 28	Reads of the Index are blocked until the next TPM Reset or TPM Restart. */
	unsigned int TPMA_NV_WRITTEN		: 1;	/* 29	Index has been written. */
	unsigned int TPMA_NV_PLATFORMCREATE	: 1;	/* 30	This Index may be undefined with Platform Authorization but not with Owner Authorization. */
	unsigned int TPMA_NV_READ_STCLEAR	: 1;	/* 31	TPM2_NV_ReadLock() may be used to SET TPMA_NV_READLOCKED for this Index. */
    };
    UINT32 val;
} TPMA_NV;

#elif defined TPM_BITFIELD_BE

typedef union {
    struct {
	unsigned int TPMA_NV_READ_STCLEAR	: 1;	/* 31	TPM2_NV_ReadLock() may be used to SET TPMA_NV_READLOCKED for this Index. */
	unsigned int TPMA_NV_PLATFORMCREATE	: 1;	/* 30	This Index may be undefined with Platform Authorization but not with Owner Authorization. */
	unsigned int TPMA_NV_WRITTEN		: 1;	/* 29	Index has been written. */
	unsigned int TPMA_NV_READLOCKED		: 1;	/* 28	Reads of the Index are blocked until the next TPM Reset or TPM Restart. */
	unsigned int TPMA_NV_CLEAR_STCLEAR	: 1;	/* 27	TPMA_NV_WRITTEN for the Index is CLEAR by TPM Reset or TPM Restart. */
	unsigned int TPMA_NV_ORDERLY		: 1;	/* 26	NV Index state is only required to be saved when the TPM performs an orderly shutdown */
	unsigned int TPMA_NV_NO_DA		: 1;	/* 25	Authorization failures of the Index do not affect the DA logic */
	unsigned int Reserved2			: 5;	/* 24:20 shall be zero reserved for future use */
	unsigned int TPMA_NV_POLICYREAD		: 1;	/* 19	The Index data may be read if the authPolicy is satisfied. */
	unsigned int TPMA_NV_AUTHREAD		: 1;	/* 18	The Index data may be read if the authValue is provided. */
	unsigned int TPMA_NV_OWNERREAD		: 1;	/* 17	The Index data can be read if Owner Authorization is provided. */
	unsigned int TPMA_NV_PPREAD		: 1;	/* 16	The Index data can be read if Platform Authorization is provided. */
	unsigned int TPMA_NV_GLOBALLOCK		: 1;	/* 15	If TPM2_NV_GlobalLock() is successful, then further writes are not permitted until the next TPM Reset or TPM Restart. */
	unsigned int TPMA_NV_WRITE_STCLEAR	: 1;	/* 14	TPM2_NV_WriteLock() may be used to prevent further writes to this location until the next TPM Reset or TPM Restart. */
	unsigned int TPMA_NV_WRITEDEFINE	: 1;	/* 13	TPM2_NV_WriteLock() may be used to prevent further writes to this location. */
	unsigned int TPMA_NV_WRITEALL		: 1;	/* 12	A partial write of the Index data is not allowed. The write size shall match the defined space size. */
	unsigned int TPMA_NV_WRITELOCKED	: 1;	/* 11	Index cannot be written. */
	unsigned int TPMA_NV_POLICY_DELETE	: 1;	/* 10	Index may not be deleted unless the authPolicy is satisfied. */
	unsigned int Reserved1 			: 2;	/* 9:8	shall be zero reserved for future use */
	unsigned int TPM_NT			: 4;	/* 7:4  The type of the index */
	unsigned int TPMA_NV_POLICYWRITE	: 1;	/* 3	Authorizations to change the Index contents that require USER role may be provided with a policy session. */
	unsigned int TPMA_NV_AUTHWRITE		: 1;	/* 2	Authorizations to change the Index contents that require USER role may be provided with an HMAC session or password. */
	unsigned int TPMA_NV_OWNERWRITE		: 1;	/* 1	The Index data can be written if Owner Authorization is provided. */
	unsigned int TPMA_NV_PPWRITE		: 1; 	/* 0	The Index data can be written if Platform Authorization is provided. */
    };
    UINT32 val;
} TPMA_NV;

#else 

typedef uint32_t TPMA_NV;

#endif

#define TPMA_NVA_PPWRITE	0x00000001
#define TPMA_NVA_OWNERWRITE	0x00000002
#define TPMA_NVA_AUTHWRITE	0x00000004
#define TPMA_NVA_POLICYWRITE	0x00000008
#define TPMA_NVA_ORDINARY	0x00000000
#define TPMA_NVA_COUNTER	0x00000010
#define TPMA_NVA_BITS		0x00000020
#define TPMA_NVA_EXTEND		0x00000040
#define TPMA_NVA_PIN_FAIL	0x00000080
#define TPMA_NVA_PIN_PASS	0x00000090
#define TPMA_NVA_RESERVED1	0x00000300
#define TPMA_NVA_POLICY_DELETE	0x00000400
#define TPMA_NVA_WRITELOCKED	0x00000800
#define TPMA_NVA_WRITEALL	0x00001000
#define TPMA_NVA_WRITEDEFINE	0x00002000
#define TPMA_NVA_WRITE_STCLEAR	0x00004000
#define TPMA_NVA_GLOBALLOCK	0x00008000
#define TPMA_NVA_PPREAD		0x00010000
#define TPMA_NVA_OWNERREAD	0x00020000
#define TPMA_NVA_AUTHREAD	0x00040000
#define TPMA_NVA_POLICYREAD	0x00080000
#define TPMA_NVA_RESERVED2	0x01f00000
#define TPMA_NVA_NO_DA		0x02000000
#define TPMA_NVA_ORDERLY	0x04000000
#define TPMA_NVA_CLEAR_STCLEAR	0x08000000
#define TPMA_NVA_READLOCKED	0x10000000
#define TPMA_NVA_WRITTEN	0x20000000
#define TPMA_NVA_PLATFORMCREATE	0x40000000
#define TPMA_NVA_READ_STCLEAR	0x80000000

#define TPMA_NV_RESERVED	(TPMA_NVA_RESERVED1 | TPMA_NVA_RESERVED2)

/* Table 197 - Definition of TPMS_NV_PUBLIC Structure */

typedef struct {
    TPMI_RH_NV_INDEX	nvIndex;	/* the handle of the data area */
    TPMI_ALG_HASH	nameAlg;	/* hash algorithm used to compute the name of the Index and used for the authPolicy */
    TPMA_NV		attributes;	/* the Index attributes */
    TPM2B_DIGEST	authPolicy;	/* optional access policy for the Index */
    UINT16		dataSize;	/* the size of the data area */
} TPMS_NV_PUBLIC;

/* Table 198 - Definition of TPM2B_NV_PUBLIC Structure */

typedef struct {
    UINT16		size;		/* size of nvPublic */
    TPMS_NV_PUBLIC	nvPublic;	/* the public area */
} NV_PUBLIC_2B;

typedef union {
    NV_PUBLIC_2B t;
    TPM2B        b;
} TPM2B_NV_PUBLIC;

/* Table 199 - Definition of TPM2B_CONTEXT_SENSITIVE Structure <IN/OUT> */

typedef struct {
    UINT16	size;
    BYTE	buffer[MAX_CONTEXT_SIZE];	/* the sensitive data */
} CONTEXT_SENSITIVE_2B;

typedef union {
    CONTEXT_SENSITIVE_2B t;
    TPM2B                b;
} TPM2B_CONTEXT_SENSITIVE;

/* Table 200 - Definition of TPMS_CONTEXT_DATA Structure <IN/OUT, S> */

typedef struct {
    TPM2B_DIGEST		integrity;	/* the integrity value */
    TPM2B_CONTEXT_SENSITIVE	encrypted;	/* the sensitive area */
} TPMS_CONTEXT_DATA;

/* Table 201 - Definition of TPM2B_CONTEXT_DATA Structure <IN/OUT> */

typedef struct {
    UINT16		size;
    BYTE		buffer[sizeof(TPMS_CONTEXT_DATA)];	
} CONTEXT_DATA_2B;

typedef union {
    CONTEXT_DATA_2B t;
    TPM2B           b;
} TPM2B_CONTEXT_DATA;

/* Table 202 - Definition of TPMS_CONTEXT Structure */

typedef struct {
    UINT64		sequence;	/* the sequence number of the context */
    TPMI_DH_CONTEXT	savedHandle;	/* the handle of the session, object or sequence */
    TPMI_RH_HIERARCHY	hierarchy;	/* the hierarchy of the context */
    TPM2B_CONTEXT_DATA	contextBlob;	/* the context data and integrity HMAC */
} TPMS_CONTEXT;
 
/* Table 203 - Context Handle Values */

#define TPM_CONTEXT_HANDLE_HMAC			0x02000000	/* an HMAC session context */
#define TPM_CONTEXT_HANDLE_POLICY_SESSION	0x03000000	/* a policy session context */
#define TPM_CONTEXT_HANDLE_TRANSIENT		0x80000000	/* an ordinary transient object */
#define TPM_CONTEXT_HANDLE_SEQUENCE		0x80000001	/* a sequence object */
#define TPM_CONTEXT_HANDLE_STCLEAR		0x80000002	/* a transient object with the stClear attribute SET */

/* Table 204 - Definition of TPMS_CREATION_DATA Structure <OUT> */

typedef struct {
    TPML_PCR_SELECTION	pcrSelect;		/* list indicating the PCR included in pcrDigest */
    TPM2B_DIGEST	pcrDigest;		/* digest of the selected PCR using nameAlg of the object for which this structure is being created */
    TPMA_LOCALITY	locality;		/* the locality at which the object was created */
    TPM_ALG_ID		parentNameAlg;		/* nameAlg of the parent */
    TPM2B_NAME		parentName;		/* Name of the parent at time of creation */
    TPM2B_NAME		parentQualifiedName;	/* Qualified Name of the parent at the time of creation */
    TPM2B_DATA		outsideInfo;		/* association with additional information added by the key creator */
} TPMS_CREATION_DATA;
 
/* Table 205 - Definition of TPM2B_CREATION_DATA Structure <OUT> */

typedef struct {
    UINT16		size;	/* size of the creation data */
    TPMS_CREATION_DATA	creationData;
} CREATION_DATA_2B;

typedef union {
    CREATION_DATA_2B t;
    TPM2B            b;
} TPM2B_CREATION_DATA;

#endif

