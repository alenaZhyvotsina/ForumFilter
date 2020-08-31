package telran.ashkelon2020.forum.dto;

import java.time.LocalDate;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor
@AllArgsConstructor
public class DatePeriodDto {
	
	LocalDate dateFrom;
	LocalDate dateTo;

}
