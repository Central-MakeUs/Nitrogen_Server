package com.nitrogen.domain.expense.dto;

import jakarta.persistence.Entity;
import lombok.*;

@Getter
@Setter
@Builder
@AllArgsConstructor
public class CategoryDetailsDTO {
    private String name;
}
