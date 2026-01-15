package com.nitrogen.domain.expense.dto.category;

import jakarta.persistence.Entity;
import lombok.*;

@Getter
@Setter
@Builder
@AllArgsConstructor
public class CategoryDetailsDTO {
    private String name;
}
