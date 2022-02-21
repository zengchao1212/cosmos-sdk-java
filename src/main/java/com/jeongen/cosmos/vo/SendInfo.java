package com.jeongen.cosmos.vo;

import lombok.Builder;
import lombok.Data;

import java.math.BigDecimal;

@Data
@Builder
public class SendInfo {
    String toAddress;
    BigDecimal amountInAtom;
}
