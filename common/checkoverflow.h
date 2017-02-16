#ifndef CHECKOVERFLOW_H
#define CHECKOVERFLOW_H

TSS2_RC
CheckOverflow (
    UINT8   *buffer,
    UINT32   bufferSize,
    UINT8   *nextData,
    UINT32   size
    );

TSS2_RC
CheckDataPointers (
    UINT8   *buffer,
    UINT8  **nextData
    );

#endif /* CHECKOVERFLOW_H */

