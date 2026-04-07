package com.nitrogen.global.config;

import com.nitrogen.domain.expense.entity.enums.EmotionType;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.format.FormatterRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebConfig implements WebMvcConfigurer {

    @Override
    public void addFormatters(FormatterRegistry registry) {
        registry.addConverter(new StringToEmotionTypeConverter());
    }

    private static class StringToEmotionTypeConverter implements Converter<String, EmotionType> {
        @Override
        public EmotionType convert(String source) {
            return EmotionType.from(source);
        }
    }
}
