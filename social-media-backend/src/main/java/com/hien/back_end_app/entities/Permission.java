package com.hien.back_end_app.entities;


import jakarta.persistence.*;
import lombok.*;

@Entity
@Table(name = "permission")
@Setter
@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Permission {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id")
    private long id;

    @Column(name = "name")
    private String name;

    @Column(name = "description")
    private String description;
}
