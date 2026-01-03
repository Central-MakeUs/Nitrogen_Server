package com.nitrogen.global.auth.service;

import com.nitrogen.domain.user.entity.User;
import com.nitrogen.domain.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserDetailService implements UserDetailsService {
    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String socialId) throws UsernameNotFoundException {
        // 이메일이 아닌 SocialId로 조회
        User user = userRepository.findBySocialId(socialId)
                .orElseThrow(() -> new UsernameNotFoundException("해당 소셜 계정을 찾을 수 없습니다."));

        return org.springframework.security.core.userdetails.User.builder()
                .username(user.getSocialId()) // 고유 식별값
                .password("")
                .authorities("ROLE_USER")
                .build();
    }
}
