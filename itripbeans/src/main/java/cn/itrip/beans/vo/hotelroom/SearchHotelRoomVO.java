package cn.itrip.beans.vo.hotelroom;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;

import java.io.Serializable;
import java.util.Date;

/**
 *
 * 查询酒店房间的vo
 * Created by zezhong.shang on 17-5-11.
 */
@ApiModel(value = "SearchHotelRoomVO",description = "查询酒店房间的VO")
public class SearchHotelRoomVO implements Serializable{

    @ApiModelProperty("[必填] 酒店ID")
    private Long hotelId;
    @ApiModelProperty("[非必填] 是否预订(0:未预定 1:预订)")
    private Integer isBook;
    @ApiModelProperty("[非必填] 是否有早餐(0:没有 1:有)")
    private Integer isHavingBreakfast;
    @ApiModelProperty("[非必填] 是否及时响应(0:不及时 1:及时)")
    private Integer isTimelyResponse;
    @ApiModelProperty("[非必填] 床型ID")
    private Long roomBedTypeId;
    @ApiModelProperty("[必填] 入职日期")
    private Date startDate;
    @ApiModelProperty("[必填] 退房日期")
    private Date endDate;

    public Date getStartDate() {
        return startDate;
    }

    public void setStartDate(Date startDate) {
        this.startDate = startDate;
    }

    public Date getEndDate() {
        return endDate;
    }

    public void setEndDate(Date endDate) {
        this.endDate = endDate;
    }

    public Long getHotelId() {
        return hotelId;
    }

    public void setHotelId(Long hotelId) {
        this.hotelId = hotelId;
    }

    public Integer getIsBook() {
        return isBook;
    }

    public void setIsBook(Integer isBook) {
        this.isBook = isBook;
    }

    public Integer getIsHavingBreakfast() {
        return isHavingBreakfast;
    }

    public void setIsHavingBreakfast(Integer isHavingBreakfast) {
        this.isHavingBreakfast = isHavingBreakfast;
    }

    public Integer getIsTimelyResponse() {
        return isTimelyResponse;
    }

    public void setIsTimelyResponse(Integer isTimelyResponse) {
        this.isTimelyResponse = isTimelyResponse;
    }

    public Long getRoomBedTypeId() {
        return roomBedTypeId;
    }

    public void setRoomBedTypeId(Long roomBedTypeId) {
        this.roomBedTypeId = roomBedTypeId;
    }
}
