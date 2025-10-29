# Reporte de Seguridad - Sistema de Control de Acceso Horario

**Fecha del análisis:** 2025-10-29
**Proyecto:** control-horario-spring
**Tecnologías:** Spring Boot 3.2.0, Java 21, H2 Database, Spring Security

---

## Resumen Ejecutivo

Se realizó un análisis exhaustivo de seguridad en la aplicación de control de acceso horario. Se identificaron **16 vulnerabilidades** distribuidas de la siguiente manera:
- **4 Críticas**
- **5 Altas**
- **4 Medias**
- **3 Bajas**

Las vulnerabilidades más críticas incluyen CSRF deshabilitado, credenciales por defecto débiles hardcodeadas, consola H2 expuesta, y falta de validación de entrada.

---

## Vulnerabilidades Críticas

### 1. CSRF (Cross-Site Request Forgery) Deshabilitado
**Severidad:** CRÍTICA
**Archivo:** `src/main/java/com/control/acceso/infrastructure/config/SecurityConfig.java:43`

**Descripción:**
La protección CSRF está completamente deshabilitada en la configuración de seguridad:
```java
.csrf(csrf -> csrf.disable())
```

**Impacto:**
Un atacante puede realizar acciones no autorizadas en nombre de usuarios autenticados (crear usuarios, eliminar registros, etc.).

**Recomendación:**
```java
.csrf(csrf -> csrf
    .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
)
```

---

### 2. Consola H2 Habilitada en Producción
**Severidad:** CRÍTICA
**Archivo:** `src/main/resources/application.properties:9-10`

**Descripción:**
```properties
spring.h2.console.enabled=true
spring.h2.console.path=/h2-console
```

**Impacto:**
Cualquier persona con acceso a la aplicación puede acceder a la consola de base de datos en `/h2-console`, ejecutar comandos SQL arbitrarios, leer toda la información sensible, y modificar/eliminar datos.

**Recomendación:**
- Deshabilitar la consola en producción
- Si es necesaria para desarrollo, usar perfiles de Spring:
```properties
# application-dev.properties
spring.h2.console.enabled=true

# application-prod.properties
spring.h2.console.enabled=false
```

---

### 3. Credenciales por Defecto Hardcodeadas
**Severidad:** CRÍTICA
**Archivo:** `src/main/java/com/control/acceso/infrastructure/config/DataInitializer.java:22-23`

**Descripción:**
```java
String adminEmail = "admin@example.com";
String adminPassword = "admin123";
```

**Impacto:**
Contraseña de administrador débil y predecible expuesta en el código fuente. Cualquier atacante que tenga acceso al código puede usar estas credenciales para obtener acceso de administrador.

**Recomendación:**
- Usar variables de entorno para credenciales iniciales
- Forzar cambio de contraseña en primer login
- Implementar política de contraseñas fuertes
```java
String adminEmail = System.getenv("ADMIN_EMAIL");
String adminPassword = System.getenv("ADMIN_PASSWORD");
```

---

### 4. Credenciales de Base de Datos en Texto Plano
**Severidad:** CRÍTICA
**Archivo:** `src/main/resources/application.properties:4-5`

**Descripción:**
```properties
spring.datasource.username=sa
spring.datasource.password=password
```

**Impacto:**
Credenciales de base de datos expuestas en el repositorio de código.

**Recomendación:**
- Usar variables de entorno
- Usar Spring Cloud Config o Vault para secretos
```properties
spring.datasource.username=${DB_USERNAME:sa}
spring.datasource.password=${DB_PASSWORD}
```

---

## Vulnerabilidades Altas

### 5. Logging de Información Sensible
**Severidad:** ALTA
**Archivos:**
- `src/main/java/com/control/acceso/application/service/UsuarioService.java:33-36, 78-79, 117-121`
- `src/main/java/com/control/acceso/infrastructure/config/DataInitializer.java:32, 46`

**Descripción:**
Se registran hashes de contraseñas y otra información sensible en logs:
```java
logger.info("Created hashed password for admin: {}", hashedPassword);
logger.info("Updating admin password. New hash: {}", hashedPassword);
```

**Impacto:**
Los hashes de contraseñas pueden ser extraídos de logs y usados en ataques offline.

**Recomendación:**
Eliminar completamente el logging de hashes de contraseñas.

---

### 6. Falta de Validación de Entrada
**Severidad:** ALTA
**Archivos:** Todos los DTOs y Entidades

**Descripción:**
No hay validaciones en ningún DTO o entidad:
- `Usuario.java` - Sin `@Email`, `@NotNull`, `@Size`
- `RegistroManualRequestDTO.java` - Sin validaciones de fechas
- `UsuarioController.java` - Sin `@Valid` en parámetros

**Impacto:**
- Inyección de datos maliciosos
- Bypass de reglas de negocio
- Datos inconsistentes en la base de datos

**Recomendación:**
```java
@Entity
public class Usuario {
    @Email(message = "Email debe ser válido")
    @NotBlank(message = "Email es obligatorio")
    private String email;

    @NotBlank(message = "Contraseña es obligatoria")
    @Size(min = 8, message = "Contraseña debe tener al menos 8 caracteres")
    private String password;

    @NotNull
    private Role role;
}

@PostMapping("/nuevo")
public String crearUsuario(@Valid @RequestBody Usuario usuario, BindingResult result) {
    if (result.hasErrors()) {
        // manejar errores
    }
    // ...
}
```

---

### 7. Falta de Rate Limiting en Login
**Severidad:** ALTA
**Archivo:** `src/main/java/com/control/acceso/infrastructure/config/SecurityConfig.java`

**Descripción:**
No hay protección contra ataques de fuerza bruta en el endpoint de login.

**Impacto:**
Un atacante puede realizar miles de intentos de login para adivinar contraseñas.

**Recomendación:**
Implementar rate limiting usando Spring Security o Bucket4j:
```java
@Bean
public RateLimiter loginRateLimiter() {
    return RateLimiter.create(5.0); // 5 intentos por segundo
}
```

---

### 8. SQL Queries Visibles en Logs
**Severidad:** ALTA
**Archivo:** `src/main/resources/application.properties:14, 21-22`

**Descripción:**
```properties
spring.jpa.show-sql=true
logging.level.org.hibernate.SQL=DEBUG
logging.level.org.hibernate.type.descriptor.sql.BasicBinder=TRACE
```

**Impacto:**
Las queries SQL con parámetros son visibles en logs, potencialmente exponiendo datos sensibles.

**Recomendación:**
Deshabilitar en producción o usar perfiles de Spring.

---

### 9. Endpoint No Implementado Llamado desde Frontend
**Severidad:** ALTA
**Archivo:** `src/main/resources/templates/admin/dashboard.html:248`

**Descripción:**
El frontend intenta llamar a `GET /usuarios/{id}` que no existe en `UsuarioController`.

**Impacto:**
Error 404, funcionalidad rota, posible vector de ataque si se implementa incorrectamente.

**Recomendación:**
Implementar el endpoint o remover la funcionalidad del frontend.

---

## Vulnerabilidades Medias

### 10. Mensajes de Error Genéricos Expuestos
**Severidad:** MEDIA
**Archivos:** Múltiples controllers

**Descripción:**
Los mensajes de excepción se pasan directamente al usuario:
```java
redirectAttributes.addFlashAttribute("error", e.getMessage());
```

**Impacto:**
Información técnica expuesta que puede ayudar a atacantes.

**Recomendación:**
Usar mensajes de error genéricos y loggear detalles internamente.

---

### 11. Base de Datos H2 en Archivo para Producción
**Severidad:** MEDIA
**Archivo:** `src/main/resources/application.properties:2`

**Descripción:**
```properties
spring.datasource.url=jdbc:h2:file:./data/control_acceso
```

**Impacto:**
H2 es una base de datos en memoria/archivo para desarrollo, no para producción.

**Recomendación:**
Usar PostgreSQL, MySQL u otra base de datos empresarial para producción.

---

### 12. Modo Debug Habilitado Globalmente
**Severidad:** MEDIA
**Archivo:** `src/main/resources/application.properties:20`

**Descripción:**
```properties
logging.level.com.control.acceso=DEBUG
```

**Impacto:**
Exceso de información en logs que puede incluir datos sensibles.

**Recomendación:**
Usar nivel INFO o WARNING en producción.

---

### 13. Caché de Thymeleaf Deshabilitado
**Severidad:** MEDIA
**Archivo:** `src/main/resources/application.properties:17`

**Descripción:**
```properties
spring.thymeleaf.cache=false
```

**Impacto:**
Degradación de rendimiento en producción.

**Recomendación:**
Habilitar caché en producción usando perfiles.

---

## Vulnerabilidades Bajas

### 14. Uso de th:inline="javascript"
**Severidad:** BAJA
**Archivos:** Varios archivos HTML

**Descripción:**
El uso de `th:inline="javascript"` puede ser vector de XSS si no se usa correctamente.

**Recomendación:**
Verificar que todas las variables interpoladas están correctamente escapadas.

---

### 15. Falta de @PreAuthorize en Métodos
**Severidad:** BAJA
**Archivos:** Controllers

**Descripción:**
No hay validación de autorización a nivel de método, solo a nivel de URL.

**Recomendación:**
```java
@PreAuthorize("hasRole('ADMIN')")
@PostMapping("/eliminar/{id}")
public ResponseEntity<String> eliminarUsuario(@PathVariable Long id) {
    // ...
}
```

---

### 16. Política de Contraseñas Débil
**Severidad:** BAJA
**Archivos:** Sistema general

**Descripción:**
No hay requisitos de complejidad para contraseñas.

**Recomendación:**
Implementar validación de contraseñas:
- Mínimo 8 caracteres
- Al menos una mayúscula
- Al menos un número
- Al menos un carácter especial

---

## Hallazgos Positivos

1. **Protección contra SQL Injection:** Uso correcto de Spring Data JPA sin queries nativas inseguras
2. **Uso de BCrypt:** Las contraseñas se hashean correctamente con BCrypt
3. **Arquitectura limpia:** Buena separación de capas (hexagonal)
4. **Uso de HTTPS ready:** Configuración compatible con HTTPS

---

## Recomendaciones Generales

1. **Implementar perfiles de Spring:**
   - `application-dev.properties` para desarrollo
   - `application-prod.properties` para producción

2. **Agregar Spring Validation:**
```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-validation</artifactId>
</dependency>
```

3. **Implementar auditoría:**
   - Usar Spring Data JPA Auditing
   - Registrar quién y cuándo modifica datos

4. **Configurar HTTPS:**
   - Forzar HTTPS en producción
   - Usar HSTS headers

5. **Implementar pruebas de seguridad:**
   - Agregar tests de seguridad con Spring Security Test
   - Implementar análisis estático con SonarQube o SpotBugs

6. **Secrets Management:**
   - Usar Spring Cloud Config Server
   - O HashiCorp Vault para secretos

7. **Monitoreo y Alertas:**
   - Implementar Spring Boot Actuator con endpoints seguros
   - Monitorear intentos de login fallidos

---

## Priorización de Correcciones

**Fase 1 (Inmediato - Crítico):**
1. Habilitar CSRF
2. Deshabilitar consola H2
3. Mover credenciales a variables de entorno
4. Eliminar logging de contraseñas

**Fase 2 (Corto plazo - Alto):**
1. Agregar validaciones de entrada
2. Implementar rate limiting
3. Deshabilitar logging SQL en producción
4. Implementar endpoint faltante o remover llamada

**Fase 3 (Medio plazo - Medio/Bajo):**
1. Migrar a base de datos de producción
2. Configurar perfiles de Spring
3. Implementar política de contraseñas
4. Agregar @PreAuthorize en métodos

---

## Conclusión

El sistema tiene una arquitectura sólida pero presenta vulnerabilidades de seguridad significativas que deben ser corregidas antes de desplegar en producción. La mayoría de las vulnerabilidades críticas pueden ser corregidas con cambios de configuración relativamente simples. Se recomienda priorizar las correcciones según la fase indicada arriba.
